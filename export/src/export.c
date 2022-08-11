/**
 * Copyright (c) 2022, tan2pow16;
 *  all rights reserved.
 *
 * This program checks the ESET quarantine folder and package
 *  all the files into a custom bundle safe for file handling.
 * After the packaging has finished, the quarantine folder will
 *  be cleared. The package can be extracted using the "extract"
 *  program to retrieve live samples.
 *
 * I am NOT responsible to any harm done to any of your devices!
 *
 * https://github.com/tan2pow16
 */

#include <stdio.h>
#include <zlib.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <ctype.h>

#define BUFSIZE 4096

/**
 * Construct full path under certain environment variable
 */
static char *getPath(const char *envi, const char *sub)
{
  char *cache;
  char *ret;

  cache = getenv(envi);
  if(cache)
  {
    ret = malloc(strlen(cache) + strlen(sub) + 2);
    sprintf(ret, "%s\\%s", cache, sub);
  }
  else
  {
    fprintf(stderr, "Unable to acquire the environment var %s.", environ);
    ret = NULL;
  }
  return ret;
}

static void cmdPause()
{
  fprintf(stdout, "\nPress 'enter' to exit.\n");
  getchar();
}

typedef struct StringNode
{
  struct StringNode *next;
  char *data;
} StringNode;

static StringNode * createNode(const char *data, StringNode *next)
{
  int len;
  StringNode *ret = malloc(sizeof(StringNode));

  if(ret)
  {
    len = strlen(data);
    ret->data = malloc(len + 1);
    if(ret->data)
    {
      memcpy(ret->data, data, len);
      ret->data[len] = 0;
      ret->next = next;
    }
    else
    {
      free(ret);
      ret = NULL;
    }
  }
  return ret;
}

/**
 * Delete ESET quarantine files that have been packaged
 */
static uint8_t deleteFile(StringNode **stackPtr)
{
  StringNode *stack = *stackPtr;

  if(stack)
  {
    if(remove(stack->data))
    {
      fprintf(stderr, "Unable to delete file '%s'.\n", stack->data);
    }
    else
    {
      fprintf(stdout, "Successfully removed file '%s'.\n", stack->data);
    }
    *stackPtr = stack->next;
    free(stack->data);
    free(stack);
  }

  return ((*stackPtr) ? 1 : 0);
}

int main(int argc, char *argv[])
{
  const char *NOD32_QUARANTINE = getPath("LOCALAPPDATA", "ESET\\ESET Security\\Quarantine");
  const char *DESKTOP = getPath("USERPROFILE", "Desktop");

  char *fileName, filePath[BUFSIZE], extCache[4], *contentRaw, *contentZip;

  size_t len, i;

  FILE *file, *output;
  long fileSize, zipSize;

  int filesCount;

  DIR *dir;
  struct dirent *dirHandle;

  z_stream zs;

  StringNode *deleteFilesStack = NULL;
  uint8_t hasError = 0;

  dir = opendir(NOD32_QUARANTINE);
  if(dir)
  {
    snprintf(filePath, BUFSIZE, "%s\\Nod32MalPack_%ld.bin", DESKTOP, time(NULL));
    output = fopen(filePath, "wb");
    if(output)
    {
      fprintf(stdout, "Writing output archive to '%s'.\n\n", filePath);
      filesCount = 0;

      while ((dirHandle = readdir(dir))) // NOT "=="!! This is assigning and test non-NULL!
      {
        fileName = dirHandle->d_name;
        len = strlen(fileName);
        if(len > 4)
        {
          for(i = 0 ; i < 4 ; i++)
          {
            extCache[i] = tolower(fileName[len - 4 + i]);
          }
          if(!memcmp(extCache, ".nqf", 4) || !memcmp(extCache, ".ndf", 4))
          {
            snprintf(filePath, BUFSIZE, "%s\\%s", NOD32_QUARANTINE, fileName);

            file = fopen(filePath, "rb");
            if(file)
            {
              fseek(file, 0L, SEEK_END);
              fileSize = ftell(file);
              rewind(file);

              contentRaw = malloc(fileSize);
              if(contentRaw)
              {
                if(fread(contentRaw, fileSize, 1, file) == 1)
                {
                  zipSize = fileSize + BUFSIZE;
                  contentZip = malloc(zipSize);
                  if(contentZip)
                  {
                    memset(&zs, 0, sizeof(zs));

                    zs.zalloc = Z_NULL;
                    zs.zfree = Z_NULL;
                    zs.opaque = Z_NULL;
                    zs.avail_in = fileSize;
                    zs.next_in = contentRaw;
                    zs.avail_out = zipSize;
                    zs.next_out = contentZip;

                    deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY);
                    deflate(&zs, Z_FINISH);
                    deflateEnd(&zs);

                    if(zs.total_out >= zipSize - 1)
                    {
                      fprintf(stderr, "WARN: Archive entry for file %s may be incomplete.\n", fileName);
                      hasError = 1;
                    }

                    zipSize = zs.total_out;

                    i = 0;
                    i += fwrite(&len, 1, 1, output);
                    i += fwrite(fileName, len, 1, output);
                    i += fwrite(&zipSize, 4, 1, output);
                    i += fwrite(contentZip, zipSize, 1, output);

                    if(i == 4)
                    {
                      fprintf(stdout, "Successfully archived file %s.\n", fileName);
                      deleteFilesStack = createNode(filePath, deleteFilesStack);
                      filesCount++;
                    }
                    else
                    {
                      fprintf(stderr, "ERROR: Archiving file %s failed. Aborting...\n", fileName);
                      cmdPause();
                      return 1;
                    }
                  }
                  else
                  {
                    fprintf(stderr, "ERROR: Unable to allocate memory with size of %d bytes. (file skipped)\n", zipSize);
                    hasError = 1;
                  }
                }
                else
                {
                  fprintf(stderr, "ERROR: Unable to read file %s. (file skipped)\n", filePath);
                  hasError = 1;
                }
              }
              else
              {
                fprintf(stderr, "ERROR: Unable to allocate memory with size of %d bytes. (file skipped)\n", fileSize);
                hasError = 1;
              }

              fclose(file);

              free(contentRaw);
              free(contentZip);
            }
            else
            {
              fprintf(stderr, "ERROR: Unable to archive file %s. (file skipped)\n", fileName);
              hasError = 1;
            }
          }
        }
      }
      closedir(dir);

      fclose(output);

      if(!hasError)
      {
        fprintf(stdout, "\nCleaning up...\n");
        while(deleteFile(&deleteFilesStack)) {}
      }

      if(filesCount > 0)
      {
        fprintf(stdout, "Successfully archived %d files.\n", filesCount);
      }
      else
      {
        fprintf(stdout, "No file is found. Output archive is blank.\n");
      }
    }
    else
    {
      fprintf(stderr, "ERROR: Unable to write output file.\n");
    }
  }
  else
  {
    fprintf(stderr, "ERROR: Unable to access NOD32 quarantine folder.\n");
  }

  cmdPause();
  return 0;
}
