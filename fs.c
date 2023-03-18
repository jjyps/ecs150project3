#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#include "disk.h"
#include "fs.h"

/* TODO: Phase 1 */
struct super_block
{
	char signature[8]; // 8
	int block_total;// 2
	int root_directory_index; // 2
	int data_block_index; // 2
	int block_count; // 2
	char fat_blocks; // 1
	char unused[BLOCK_SIZE]; // 4079
};

struct file_info
{
	char filename[16];
	int32_t file_size;
	int data_index;
	char unused[10];
};

struct file_descriptors
{
	char filename[16];
	int offset;
};

struct super_block *sb;
uint16_t *fat;
struct file_info rd[FS_FILE_MAX_COUNT];

struct file_descriptors open_files[FS_OPEN_MAX_COUNT];

int fs_mount(const char *diskname)
{
	/* TODO: Phase 1 */
	if (diskname == NULL) 
	{
		return -1;
	}

	if (block_disk_open(diskname) == -1)
	{
		
		return -1;
	}

	int block_count = block_disk_count();
	int fat_blocks = ceil((float)block_count * 2 / BLOCK_SIZE);
	int data_block_size = block_count - fat_blocks - 2;


	sb = malloc(sizeof(struct super_block));

	memcpy(sb->signature, "ECS150FS", 8);
	sb->block_total = block_count;
	sb->fat_blocks = fat_blocks;
	sb->root_directory_index = fat_blocks + 1;
	sb->data_block_index = (fat_blocks + 1) + 1;
	sb->block_count = data_block_size;

	block_read(sb->root_directory_index, rd);


	fat = malloc(sb->block_count * sizeof(uint16_t));
	int fat_bytes_read = 0;

	for (int i = 1 ; i <= sb->fat_blocks ; i++)
	{
		uint16_t *fat_block = malloc(BLOCK_SIZE);
		block_read(i, fat_block);
		memcpy(fat + fat_bytes_read, fat_block, BLOCK_SIZE);
		fat_bytes_read += BLOCK_SIZE;
	}
	fat[0] = 0xFFFF;

	empty_open_files();
	char *buf = malloc(4096);
	block_read(sb->data_block_index, buf);

	char *data_block1 = malloc(4096);
	char *data_block2 = malloc(4096);
	block_read(sb->data_block_index, data_block1);
	block_read(sb->data_block_index + 1, data_block2);



	return 0;
}

int fs_umount(void)
{
	
	int fat_bytes_written = 0;
	for (int fat_block = 1 ; fat_block <= sb->fat_blocks ; fat_block++)
	{
		uint16_t *block_fat = malloc(BLOCK_SIZE);
		memcpy(block_fat, fat + fat_bytes_written, BLOCK_SIZE);
		block_write(fat_block, block_fat);
		fat_bytes_written += BLOCK_SIZE;
	}

	block_write(sb->root_directory_index, rd);
	memset(open_files, 0, sizeof(open_files));



	empty_open_files();

	block_disk_close();
	return 0;
}

int empty_open_files()
{
	for (int i = 0 ; i < FS_OPEN_MAX_COUNT ; i++)
	{
		strcpy(open_files[i].filename, "\0");
		
	}
}

int fs_info(void)
{
	int free_fat = 0;
	int free_rdir = 0;
	// Error Handling for when virtual disk is not opened
	if (sb == NULL) 
	{
		return -1;
	}

	// Function to find the fat free ratio
	for (int i = 0; i < sb->block_count; i++) {
		if (fat[i] == 0)
		free_fat++;
	}

	// Function to find the rdir free ratio
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (*rd[i].filename == '\0')
		free_rdir++;
	}

	printf("FS Info:\n");
	printf("total_blk_count=%d\n", sb->block_total);
	printf("fat_blk_count=%d\n", sb->fat_blocks);
	printf("rdir_blk=%d\n", sb->root_directory_index);
	printf("data_blk=%d\n", sb->data_block_index);
	printf("data_blk_count=%d\n", sb->block_count);
	printf("fat_free_ratio=%d/%d\n", free_fat, sb->block_count);
	printf("rdir_free_ratio=%d/%d\n", free_rdir, FS_FILE_MAX_COUNT);
	return 0;
}

int fs_create(const char *filename)
{
	/* TODO: Phase 2 */
	for (int i = 0 ; i < FS_OPEN_MAX_COUNT ; i++)
	{	
		if (strcmp(rd[i].filename,filename) == 0)
		{
			return -1;
		}
	}
	
	// Find an empty file descriptor in the root directory
	for (int i = 0 ; i < FS_FILE_MAX_COUNT ; i++) {
		if (*rd[i].filename == '\0')
		{
			// Found empty file descriptor, then fill in with filename 
			strcpy(rd[i].filename, filename);
			rd[i].data_index = 0xFFFF;
			rd[i].file_size = 0;
			return 0;
		}
	}

	return -1;
}

int fs_delete(const char *filename)
{
	/* TODO: Phase 2 */

	// Finding the file in the root directory
	struct file_info file;
	for (int i = 0 ; i < FS_OPEN_MAX_COUNT ; i++)
	{
		if (strcmp(rd[i].filename,filename) == 0) {
			file = rd[i];
			rd[i].data_index = 0xFFFF;
			strcpy(rd[i].filename, "\0");
			rd[i].file_size = 0;
		}
	}

	// Label all the blocks related with the file as Free
	int index = file.data_index;
	while (index != 0xFFFF) 
	{
		int next_index = fat[index];
		fat[index] = 0;
		index = next_index;
	}
	
	return 0;
}

int fs_ls(void)
{
	/* TODO: Phase 2 */

	printf("FS Ls:\n");

	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		if (*rd[i].filename == '\0') {
			continue;
		}
		printf("file: %s, size: %d, data_blk: %d\n", rd[i].filename, rd[i].file_size, rd[i].data_index);
	}
	return 0;
}

int fs_open(const char *filename)
{
	// Loop through and find a open file descriptor, if full return -1
	int fd = -1;
	if (!filename)
	{
		return -1;
	}


	for (int i = 0 ; i < FS_OPEN_MAX_COUNT ; i++)
	{	
		if (strcmp(open_files[i].filename,"\0") == 0)
		{
			strcpy(open_files[i].filename, filename);
			open_files[i].offset = 0;
			fd = i;
			break;
		}
	}

	return fd;
}

int fs_close(int fd)
{
	if (fd < 0 || fd > FS_OPEN_MAX_COUNT)
	{
		return -1;
	} 
	strcpy(open_files[fd].filename, "\0");


	return 0;
}

int fs_stat(int fd)
{
	if (fd < 0 || fd > FS_OPEN_MAX_COUNT)
	{
		return -1;
	} 
	// Error handlers

	int size = 0;
	char *filename = open_files[fd].filename;

	for (int i = 0 ; i < FS_FILE_MAX_COUNT ; i++) {
		if (strcmp(rd[i].filename,filename) == 0)
		{
			size = rd[i].file_size;
			break;
		}
	}

	return size;
}

int fs_lseek(int fd, size_t offset)
{
	if (fd < 0 || fd > FS_OPEN_MAX_COUNT || offset < 0)
	{
		return -1;
	} 
	open_files[fd].offset = offset;
	return 0;
}

int fs_write(int fd, void *buf, size_t count)
{	
	if (fd < 0 || fd > FS_OPEN_MAX_COUNT || count < 0)
	{
		return -1;
	}

	int file_size = get_file_size(fd);
	int offset = open_files[fd].offset;
	if (file_size != 0)
	{
		void *new_buf = malloc(((offset + count + BLOCK_SIZE - 1) / BLOCK_SIZE));
		
		void *old_buf = malloc((offset + BLOCK_SIZE - 1) / BLOCK_SIZE);

		int save_offset = open_files[fd].offset;
		open_files[fd].offset = 0;
		fs_read(fd, old_buf, offset);

		memcpy(new_buf, old_buf, offset);
		memcpy(new_buf + offset, buf, count + offset);		

		wipe_file(open_files[fd].filename);
		fs_write(fd, new_buf, count + offset);
	}

    int file_remainder = file_size % BLOCK_SIZE;
    int bytes_written = 0;
    int bytes_to_write = BLOCK_SIZE;
    
    int block_span = (count + file_remainder + (BLOCK_SIZE - 1)) / BLOCK_SIZE;

    for (int i = 0 ; i < block_span ; i++)
    {
        if (count + file_remainder < bytes_to_write)
        {
            bytes_to_write = count + file_remainder;
        }
        void *block_buf = malloc(BLOCK_SIZE);

        int block_num = get_data_block(fd);


		block_read(block_num + sb->data_block_index, block_buf);

		void *temp_buf = malloc(BLOCK_SIZE);
		memcpy(temp_buf, buf + bytes_written, BLOCK_SIZE);


        memcpy(block_buf + file_remainder, temp_buf, BLOCK_SIZE);

        void *new_block = malloc(BLOCK_SIZE);
        memcpy(new_block, block_buf, BLOCK_SIZE);


        block_write(block_num + sb->data_block_index, new_block);

        bytes_written += bytes_to_write - file_remainder;
		update_file_size(fd, bytes_to_write - file_remainder);

        file_remainder = 0;
        count -= bytes_written;
    }

	open_files[fd].offset += bytes_written;
    return bytes_written;
}

int wipe_file(const char *filename)
{
	/* TODO: Phase 2 */

	// Finding the file in the root directory
	struct file_info file;
	for (int i = 0 ; i < FS_OPEN_MAX_COUNT ; i++)
	{
		if (strcmp(rd[i].filename,filename) == 0) {
			file = rd[i];
			rd[i].data_index = 0xFFFF;
			rd[i].file_size = 0;
		}
	}

	// Label all the blocks related with the file as Free
	int index = file.data_index;
	while (index != 0xFFFF) 
	{
		int next_index = fat[index];
		fat[index] = 0;
		index = next_index;
	}
	
	return 0;
}

int fs_read(int fd, void *buf, size_t count)
{
	if (fd < 0 || fd > FS_OPEN_MAX_COUNT || count < 0)
	{
		return -1;
	}

    int file_size = get_file_size(fd);
    int start_data_index = get_start_data_index(fd);
	
    void *file = malloc(file_size);
    int offset = open_files[fd].offset;
	int remaing_file_size = file_size;
    
    int bytes_in_block = BLOCK_SIZE;
    int block_span = (file_size + (BLOCK_SIZE - 1)) / BLOCK_SIZE;

    int bytes_read = 0;
    
    for (int i = 0 ; i < block_span ; i++)
    {
        if (remaing_file_size < bytes_in_block)
        {
            bytes_in_block = remaing_file_size;
        }

        void *block_buf = malloc(BLOCK_SIZE);

        block_read(start_data_index + sb->data_block_index, block_buf);

        memcpy(file + bytes_read, block_buf, BLOCK_SIZE);

        start_data_index = fat[start_data_index];
        bytes_read += bytes_in_block;
		remaing_file_size -= bytes_in_block;
    }
    
    if (count > bytes_read)
    {
        count = bytes_read - offset;
    }
    memcpy(buf, file + offset, count);
	
    open_files[fd].offset += count;
    return count;
}

int get_start_data_index(int fd)
{
	// Get the filename, then open
	char *filename = open_files[fd].filename;
  	int data_index = -1;

	// Iterate over all the directory entries
	for (int i = 0 ; i < FS_FILE_MAX_COUNT ; i++)
	{
		// If the current directory matches the given filename, set the file size
		if (strcmp(rd[i].filename,filename) == 0) {
			data_index = rd[i].data_index;
			break;
		}
	}
	return data_index;
}

int get_data_block(int fd)
{
    // ALLOCATING
    int allocated_data_block = -1;

    int file_size = get_file_size(fd);
    int file_remainder = file_size % BLOCK_SIZE;
    
    if (file_remainder == 0)
    {
        for (int i = 1 ; i < sb->block_count; i++)
        {
            if (fat[i] == 0)
            {
                allocated_data_block = i;
                fat[i] = 0xFFFF;
                break;
            }
        }
    }
    else
    {
        int curr_index = get_data_index_on_rd(fd);


        while(fat[curr_index] != 0xFFFF)
        {
            curr_index = fat[curr_index];
        }
        allocated_data_block = curr_index;
    }

    //LINKING
    if (file_size == 0)
    {
		set_fat_index_on_rd(fd, allocated_data_block);
        // open_files[fd].data_index = allocated_data_block;
    }
    else if (file_size != 0 && file_remainder == 0)
    {
        int curr = get_data_index_on_rd(fd);
        while(fat[curr] != 0xFFFF)
        {
            curr = fat[curr];
        }
        fat[curr] = allocated_data_block;
    }

    return allocated_data_block;

}

int get_data_index_on_rd(int fd)
{
	char *filename = open_files[fd].filename;
  	int data_index = -1;

	// Loop through the directory entries
	for (int i = 0 ; i < FS_FILE_MAX_COUNT ; i++)
	{
		// If the file name mathces, update the data index
		if (strcmp(rd[i].filename,filename) == 0) {

			data_index = rd[i].data_index;
		}
	}
	return data_index;
}

int get_available_data_block()
{
	// Get the total number of data blocks in the system
	int total_data_blocks = block_disk_count();

	// Iterate over all the data blocks
	for (int i = 0 ; i < total_data_blocks ; i++)
	{
		if(fat[i] == 0)
		{
			return i;
		}
	}
	return -1;
}

int get_file_size(int fd)
{
	// Get the filename, then open
	char *filename = open_files[fd].filename;
  	int file_size = -1;

	// Iterate over all the directory entries
	for (int i = 0 ; i < FS_FILE_MAX_COUNT ; i++)
	{
		// If the current directory matches the given filename, set the file size
		if (strcmp(rd[i].filename,filename) == 0) {
			file_size = rd[i].file_size;
			break;
		}
	}
	return file_size;
}

void update_file_size(int fd, int bytes_to_add)
{
	char *filename = open_files[fd].filename;
  	int file_size = -1;


	for (int i = 0 ; i < FS_FILE_MAX_COUNT ; i++)
	{
		// If the entry matches, update the file size
		if (strcmp(rd[i].filename,filename) == 0) {
			rd[i].file_size += bytes_to_add;
			break;
		}
	}
}

void set_fat_index_on_rd(int fd, int fat_index)
{
	char *filename = open_files[fd].filename;
  	int file_size = -1;

	if (fat_index == 255)
	{
		//("HEREE WE FOUND IT %d\n", fat_index);
	}

	// Loop through the directory entries
	for (int i = 0 ; i < FS_FILE_MAX_COUNT ; i++)
	{
		// If the file name mathces, update the data index
		if (strcmp(rd[i].filename,filename) == 0) {
			rd[i].data_index = fat_index;
		}
	}
}

int link_data_block(int fd, int new_fat_index)
{
	int filesize = get_file_size(fd);


	// IF THIS IS A FRESH FILE
	if (filesize == 0)
	{
		char *filename = open_files[fd].filename;
		for (int i = 0 ; i < FS_FILE_MAX_COUNT ; i++)
		{
			if (strcmp(rd[i].filename,filename) == 0) {
				rd[i].data_index = new_fat_index;
			}
		}
	}
	// ELSE HAS EXISITING DATA BLOCKS, NEEDS TO GO INTO THE FAT TO LINK
	// else 
	// {	}
}