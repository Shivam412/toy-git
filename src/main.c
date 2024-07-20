#include "stdio.h"
#include "sys/stat.h"
#include "sys/types.h"
#include "errno.h"
#include "string.h"
#include "zlib.h"
#include "assert.h"
#include "stdlib.h"
#include "stdbool.h"
#include "stddef.h"
#include "dirent.h"

#include "openssl/evp.h"
#include "openssl/sha.h"

#define MAX_PATH_LENGTH 100
#define CHUNK_SIZE 16384
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

typedef char *string;
typedef char *bytes;

const string INIT = "init";
const string CAT_FILE = "cat-file";
const string HASH_OBJECT = "hash-object";
const string LS_TREE = "ls-tree";
const string WRITE_TREE = "write-tree";

const string skip_dirs_list[] = {".", "..", ".git"};

typedef struct Git_object
{
    char type[32];
    size_t size;
    bytes data;
} Git_object;

typedef struct Def_object
{
    unsigned char *data;
    size_t size;
} Def_object;

bool should_skip(const string full_name)
{
    for (size_t i = 0; i < ARRAY_SIZE(skip_dirs_list); i++)
    {
        if (strcmp(skip_dirs_list[i], full_name) == 0)
            return true;
    }
    return false;
}

void constructFilePath(const string hash, string path)
{
    snprintf(path, MAX_PATH_LENGTH, ".git/objects/%.2s/%s", hash, hash + 2);
}

string hash_from_bytes(unsigned char digest[20])
{
    static char hex_str[41];
    for (size_t i = 0; i < 20; i++)
        sprintf(hex_str + 2 * i, "%02x", digest[i]);

    return hex_str;
}

int init()
{
    const string dirs[] = {".git", ".git/objects", ".git/refs"};

    for (size_t i = 0; i < ARRAY_SIZE(dirs); i++)
    {
        int result = mkdir(dirs[i], 0755);
        if (result != 0)
        {
            fprintf(stderr, "[ERROR] mkdir failed: %s\n", strerror(errno));
            return result;
        }
    }

    FILE *file = fopen(".git/HEAD", "w");
    fprintf(file, "ref: refs/heads/master\n");
    fclose(file);

    return 0;
}

/* report a zlib or i/o error */
void zerr(int ret)
{
    fprintf(stderr, "zpipe: ");
    switch (ret)
    {
    case Z_ERRNO:
        if (ferror(stdin))
            fprintf(stderr, "error reading stdin: %s\n", strerror(errno));
        if (ferror(stdout))
            fprintf(stderr, "error writing stdout: %s\n", strerror(errno));
        break;
    case Z_STREAM_ERROR:
        fprintf(stderr, "invalid compression level\n");
        break;
    case Z_DATA_ERROR:
        fprintf(stderr, "invalid or incomplete deflate data\n");
        break;
    case Z_MEM_ERROR:
        fprintf(stderr, "out of memory\n");
        break;
    case Z_VERSION_ERROR:
        fprintf(stderr, "zlib version mismatch!\n");
        break;
    default:
        fprintf(stderr, "unknown zlib error: %s\n", zError(ret));
        break;
    }
}

// char** buffer == str* buffer
int inf(FILE *source, bytes *buffer, size_t *buffer_size)
{
    int ret;
    unsigned have;
    z_stream stream;
    unsigned char in[CHUNK_SIZE];
    unsigned char out[CHUNK_SIZE];

    /* allocate inflate state */
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = 0;
    stream.next_in = Z_NULL;
    ret = inflateInit(&stream);
    if (ret != Z_OK)
    {
        return ret;
    }

    do
    {
        stream.avail_in = fread(in, 1, CHUNK_SIZE, source);
        if (ferror(source))
        {
            (void)inflateEnd(&stream);
            return Z_ERRNO;
        }
        if (stream.avail_in == 0)
            break;
        stream.next_in = in;

        /* run inflate on input until output buffer not full.*/
        do
        {
            stream.avail_out = CHUNK_SIZE;
            stream.next_out = out;
            ret = inflate(&stream, Z_NO_FLUSH);
            assert(ret != Z_STREAM_ERROR);
            switch (ret)
            {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                (void)inflateEnd(&stream);
                return ret;
            }
            have = CHUNK_SIZE - stream.avail_out;
            *buffer = realloc(*buffer, *buffer_size + have);
            if (buffer == NULL)
            {
                (void)inflateEnd(&stream);
                return Z_MEM_ERROR;
            }
            memcpy(*buffer + *buffer_size, out, have);
            *buffer_size += have;
        } while (stream.avail_out == 0);
    } while (ret != Z_STREAM_END);

    /* clean up and return */
    (void)inflateEnd(&stream);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

Def_object *def_string(string str, int size, int level)
{
    z_stream stream;
    Def_object *def = malloc(sizeof(Def_object));
    def->data = malloc(CHUNK_SIZE);

    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    int ret = deflateInit(&stream, level);
    if (ret != Z_OK)
        return NULL;

    stream.avail_in = size;
    stream.next_in = (unsigned char *)str;

    stream.avail_out = CHUNK_SIZE;
    stream.next_out = def->data;
    ret = deflate(&stream, Z_FINISH);

    def->size = CHUNK_SIZE - stream.avail_out;

    (void)deflateEnd(&stream);
    return def;
}

int def_file(FILE *source, FILE *dest, int level, EVP_MD_CTX *md_ctx, size_t file_size)
{
    bool write_header = false;
    int ret, flush;
    unsigned int have;
    z_stream stream;
    unsigned char in[CHUNK_SIZE];
    unsigned char out[CHUNK_SIZE];

    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    ret = deflateInit(&stream, level);
    if (ret != Z_OK)
        return ret;

    do
    {
        if (write_header == false)
        {
            sprintf((bytes)in, "blob %zu", file_size);
            stream.avail_in = strlen((bytes)in) + 1;
            in[stream.avail_in] = '\0';
            write_header = true;
        }
        else
        {
            stream.avail_in = fread(in, 1, CHUNK_SIZE, source);
        }

        if (ferror(source))
        {
            (void)deflateEnd(&stream);
            return Z_ERRNO;
        }
        flush = feof(source) ? Z_FINISH : Z_NO_FLUSH;
        stream.next_in = in;
        // compute sha1 hash.
        EVP_DigestUpdate(md_ctx, in, stream.avail_in);

        do
        {
            stream.avail_out = CHUNK_SIZE;
            stream.next_out = out;
            ret = deflate(&stream, flush);
            assert(ret != Z_STREAM_ERROR);
            have = CHUNK_SIZE - stream.avail_out;

            if (fwrite(out, 1, have, dest) != have || ferror(dest))
            {
                (void)deflateEnd(&stream);
                return Z_ERRNO;
            }

        } while (stream.avail_out == 0);
    } while (flush != Z_FINISH);
    assert(ret == Z_STREAM_END);

    (void)deflateEnd(&stream);
    return Z_OK;
}

Git_object *read_object(const string hash)
{
    if (hash == NULL)
    {
        fprintf(stderr, "[ERROR] Invalid hash\n");
        return NULL;
    }
    if (strlen(hash) != 40)
    {
        fprintf(stderr, "[ERROR] Invalid hash size\n");
        return NULL;
    }
    char path[MAX_PATH_LENGTH];
    constructFilePath(hash, path);

    FILE *fptr = fopen(path, "rb");
    if (fptr == NULL)
    {
        fprintf(stderr, "[ERROR] Opening file %s : %s\n", path, strerror(errno));
        return NULL;
    }

    bytes buffer = NULL;
    size_t buffer_size = 0;
    int ret = inf(fptr, &buffer, &buffer_size);
    if (ret != Z_OK)
    {
        fprintf(stderr, "[ERROR] Couldn't read zlib file %s\n", zError(ret));
        fclose(fptr);
        return NULL;
    }

    char header[32];
    size_t content_size = 0;
    sscanf(buffer, "%s %zu", header, &content_size);

    // count 1 for appended null terminator
    size_t header_size = strlen(header) + snprintf(NULL, 0, "%zu", content_size) + 1;
    assert(buffer_size - 1 == header_size + content_size);

    Git_object *object = malloc(sizeof(Git_object));
    // type of object.
    memcpy(object->type, header, 32);
    // content size.
    object->size = content_size;
    // content of object.
    object->data = malloc(content_size + 1);
    memcpy(object->data, buffer + header_size, content_size + 1);

    free(buffer);
    fclose(fptr);
    return object;
}

int cat_file(const string hash)
{
    Git_object *object = read_object(hash);

    if (object == NULL)
    {
        fprintf(stderr, "[ERROR] could not read object");
        return -1;
    }

    // print buffer
    fwrite(object->data, 1, object->size, stdout);
    fputc('\n', stdout);

    free(object->data);
    free(object);
    return 0;
}

unsigned char *hash_buffer(const char *buffer, size_t size)
{
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha1();
    unsigned char *digest = malloc(20 * sizeof(unsigned char));

    if (md_ctx == NULL)
    {
        fprintf(stderr, "Error creating MD context\n");
        return NULL;
    }

    if (!EVP_DigestInit_ex(md_ctx, md, NULL))
    {
        fprintf(stderr, "Error initializing digest\n");
        EVP_MD_CTX_free(md_ctx);
        return NULL;
    }

    if (!EVP_DigestUpdate(md_ctx, buffer, size))
    {
        fprintf(stderr, "Error updating digest\n");
        EVP_MD_CTX_free(md_ctx);
        return NULL;
    }

    if (!EVP_DigestFinal_ex(md_ctx, digest, NULL))
    {
        fprintf(stderr, "Error finalizing digest\n");
        EVP_MD_CTX_free(md_ctx);
        return NULL;
    }

    EVP_MD_CTX_free(md_ctx);
    return digest;
}

unsigned char *hash_file(const string file_path)
{
    FILE *file = fopen(file_path, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "[ERROR] Opening file %s : %s\n", file_path, strerror(errno));
        return NULL;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha1();

    EVP_DigestInit_ex(md_ctx, md, NULL);

    // hash blob
    fseek(file, 0L, SEEK_END);
    size_t file_size = ftell(file);
    // Set the position of the file pointer to begin of the file.
    fseek(file, 0L, SEEK_SET);

    FILE *tmp_file = fopen("/tmp/tmpfile", "wb");
    if (def_file(file, tmp_file, 1, md_ctx, file_size) != Z_OK)
    {
        fprintf(stderr, "[ERROR] Couldn't deflate file\n");
        fclose(tmp_file);
        fclose(file);
        return NULL;
    }

    unsigned char *digest = malloc(20 * sizeof(unsigned char));
    EVP_DigestFinal_ex(md_ctx, digest, NULL);
    EVP_MD_CTX_free(md_ctx);

    string hex_str = hash_from_bytes(digest);

    char path[MAX_PATH_LENGTH];
    sprintf(path, ".git/objects/%.2s", hex_str);
    mkdir(path, 0777);

    constructFilePath(hex_str, path);
    // Create a file to rename into.
    if (rename("/tmp/tmpfile", path) != 0)
    {
        fprintf(stderr, "[ERROR] Couldn't rename file : %s\n", strerror(errno));
        return NULL;
    }

    fclose(file);
    fclose(tmp_file);
    return digest;
}

int hash_object(const string file_path)
{
    unsigned char *digest = hash_file(file_path);
    string hash = hash_from_bytes(digest);
    if (hash == NULL)
    {
        fprintf(stderr, "[ERROR] Unable to hash the file %s\n", file_path);
        return -1;
    }
    printf("%s\n", hash);
    return 0;
}

int ls_tree(const string hash)
{
    Git_object *object = read_object(hash);
    if (object == NULL)
    {
        fprintf(stderr, "[ERROR] could not read object");
        return -1;
    }

    assert(strcmp(object->type, "tree") == 0);
    size_t i = 1;
    while (i < object->size)
    {
        size_t mode = 0;
        char filename[255];
        sscanf(object->data + i, "%zu %s", &mode, filename);
        if (mode == 0)
        {
            fprintf(stderr, "[ERROR] Invalid mode in tree entry: %zu\n", mode);
            return -1;
        }
        size_t total_size_wo_sha = strlen(filename) + 1 + snprintf(NULL, 0, "%zu", mode) + 1;

        char hex_str[41];
        for (size_t j = 0; j < 20; j++)
        {
            unsigned char c = *(object->data + i + total_size_wo_sha + j);
            sprintf(hex_str + 2 * j, "%02x", c);
        }
        i += total_size_wo_sha + 20;

        // read the hash and tell what kind of object it is.
        char _path[MAX_PATH_LENGTH];
        constructFilePath(hex_str, _path);

        Git_object *_object = read_object(hex_str);
        printf("%04zu %s %s\t%s\n", mode, _object->type, hex_str, filename);

        free(_object->data);
        free(_object);
    }
    free(object->data);
    free(object);
    return 0;
}

bool is_executable(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
    {
        // check if the path is executable
        if ((st.st_mode & S_IFMT) == S_IFREG && (st.st_mode & S_IXUSR))
            return true;
        else
            return false;
    }
    return false;
}

unsigned char *write_tree(const string path)
{
    DIR *dir;
    struct dirent *file_info;

    if ((dir = opendir(path)) == NULL)
    {
        fprintf(stderr, "[ERROR] Couldn't open current directory\n");
        return NULL;
    }

    string current_snapshot = malloc(1);
    size_t current_snapshot_size = 0;
    current_snapshot[0] = '\0';

    while ((file_info = readdir(dir)) != 0)
    {
        if (should_skip(file_info->d_name))
            continue;

        char full_name[1000];
        snprintf(full_name, sizeof(full_name), "%s/%s", path, file_info->d_name);

        string mode = "100644";
        string name = file_info->d_name;
        unsigned char *digest = malloc(20);

        if (file_info->d_type == DT_LNK)
        {
            mode = "12000";
        }
        if (file_info->d_type == DT_REG)
        {
            if (is_executable(full_name))
            {
                mode = "100755";
            }
            digest = hash_file(full_name);
        }
        if (file_info->d_type == DT_DIR)
        {
            mode = "4000";
            digest = write_tree(full_name);
        }
        size_t next_size = strlen(mode) + strlen(name) + 2 + 20;
        current_snapshot = realloc(current_snapshot, current_snapshot_size + next_size);
        sprintf(current_snapshot + current_snapshot_size, "%s %s%c%s", mode, name, '\0', digest);
        current_snapshot_size += next_size;
    }
    // prepare header and tree object.
    size_t content_size = snprintf(NULL, 0, "%zu", current_snapshot_size);
    size_t header_size = strlen("tree") + 1 + content_size + 1;
    string tree_object = malloc(header_size + current_snapshot_size);
    sprintf(tree_object, "tree %zu%c", current_snapshot_size, '\0');
    memcpy(tree_object + header_size, current_snapshot, current_snapshot_size);

    unsigned char *digest = hash_buffer(tree_object, header_size + current_snapshot_size);

    // Create a file and write tree object;
    string hash = hash_from_bytes(digest);
    char tree_object_path[MAX_PATH_LENGTH];
    sprintf(tree_object_path, ".git/objects/%.2s", hash);
    mkdir(tree_object_path, 0777);
    constructFilePath(hash, tree_object_path);

    FILE *file = fopen(tree_object_path, "wb");
    Def_object *compressed = def_string(tree_object, header_size + current_snapshot_size, 1);
    fwrite(compressed->data, compressed->size, 1, file);
    fclose(file);

    free(current_snapshot);
    free(tree_object);
    free(compressed->data);
    free(compressed);
    closedir(dir);

    return digest;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "[ERROR] No arguments provided\n");
        return -1;
    }

    if (strcmp(argv[1], INIT) == 0)
    {
        return init();
    }
    else if (strcmp(argv[1], CAT_FILE) == 0)
    {
        return cat_file(argv[2]);
    }
    else if (strcmp(argv[1], HASH_OBJECT) == 0)
    {
        return hash_object(argv[2]);
    }
    else if (strcmp(argv[1], LS_TREE) == 0)
    {
        return ls_tree(argv[2]);
    }
    else if (strcmp(argv[1], WRITE_TREE) == 0)
    {
        unsigned char *digest = write_tree(".");
        if (digest == NULL)
        {
            fprintf(stderr, "[ERROR] Failed to write tree.\n");
        }
        printf("%s\n", hash_from_bytes(digest));
        free(digest);
        return 0;
    }
    return 0;
}