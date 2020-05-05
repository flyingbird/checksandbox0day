#import "substrate.h"
#import <mach-o/dyld.h>
#import <mach-o/swap.h>
#import <mach-o/fat.h>

/*
 * Structure of an embedded-signature MultiBlob (called a SuperBlob in the codesign source)
 */
typedef struct __BlobIndex {
    uint32_t type;                   /* type of entry */
    uint32_t offset;                 /* offset of entry */
} CS_Blob;

typedef struct __MultiBlob {
    uint32_t magic;                  /* magic number */
    uint32_t length;                 /* total length of SuperBlob */
    uint32_t count;                  /* number of index entries following */
    CS_Blob index[];                 /* (count) entries */
    /* followed by Blobs in no particular order as indicated by offsets in index */
} CS_MultiBlob;

static uint32_t read_uint32(FILE *obj_file, off_t offset) {
  uint32_t magic;
  fseek(obj_file, offset, SEEK_SET);
  fread(&magic, sizeof(uint32_t), 1, obj_file);
  return magic;
}

static void *load_bytes(FILE *obj_file, off_t offset, size_t size) {
  void *buf = calloc(1, size);
  fseek(obj_file, offset, SEEK_SET);
  fread(buf, size, 1, obj_file);
  return buf;
}

static NSMutableArray *passArray = nil;

@interface FBApplicationInfo
@property (nonatomic,readonly) NSURL * executableURL;
@property (nonatomic,copy,readonly) NSString * bundleIdentifier;
-(NSString *)getEvilEntitlements:(NSString *)file;
@end

%hook FBApplicationInfo

%new
-(NSString *)getEvilEntitlements:(NSString *)file {
	FILE *obj_file = fopen([file UTF8String],"r");
	if (obj_file != NULL) {
		uint32_t magic = read_uint32(obj_file, 0);
		int is_64 = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
		int is_swap = (magic == MH_CIGAM || magic == MH_CIGAM_64 || magic == FAT_CIGAM);
		int fat = (magic == FAT_MAGIC || magic == FAT_CIGAM);
		off_t mach_header_offset = 0;
		
		if (fat) {
			size_t header_size = sizeof(struct fat_header);
			size_t arch_size = sizeof(struct fat_arch);
			off_t arch_offset = (off_t)header_size;
			struct fat_arch *arch = load_bytes(obj_file, arch_offset, arch_size);
			if (is_swap) {
			  swap_fat_arch(arch, 1, 0);
			}
			mach_header_offset = (off_t)arch->offset;
			free(arch);

			magic = read_uint32(obj_file, mach_header_offset);
			is_64 = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
			is_swap = (magic == MH_CIGAM || magic == MH_CIGAM_64 || magic == FAT_CIGAM);
		}
		
		uint32_t ncmds;
		if (is_64) {
			size_t header_size = sizeof(struct mach_header_64);
			struct mach_header_64 *header = load_bytes(obj_file, mach_header_offset, header_size);
			if (is_swap) {
			  swap_mach_header_64(header, 0);
			}
			ncmds = header->ncmds;
			free(header);
		} else {
			size_t header_size = sizeof(struct mach_header);
			struct mach_header *header = load_bytes(obj_file, mach_header_offset, header_size);
			if (is_swap) {
			  swap_mach_header(header, 0);
			}
			ncmds = header->ncmds;
			free(header);
		}
		
		off_t cursor = mach_header_offset + (is_64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
		for (uint32_t i = 0; i < ncmds; i++) {
			struct segment_command *segmentCommand = load_bytes(obj_file, cursor, sizeof(struct segment_command));
			if (segmentCommand->cmd != LC_CODE_SIGNATURE) {
				cursor += segmentCommand->cmdsize;
				free(segmentCommand);
				continue; 
			}
	
			const struct linkedit_data_command *dataCommand = (const struct linkedit_data_command *)segmentCommand;
			off_t dataStart = mach_header_offset + dataCommand->dataoff;
			CS_MultiBlob *multiBlob = load_bytes(obj_file, dataStart, sizeof(CS_MultiBlob));
			if (ntohl(multiBlob->magic) != 0xfade0cc0) { free(multiBlob);free(segmentCommand);fclose(obj_file);return nil; }
			
			uint32_t count = ntohl(multiBlob->count);
			free(multiBlob);
			multiBlob = load_bytes(obj_file, dataStart, sizeof(uint32_t)*3+sizeof(uint32_t)*2*count);
			
			for (int i = 0; i < count; i++) {
				off_t blobBytes = dataStart + ntohl(multiBlob->index[i].offset);
				uint32_t blobMagic = ntohl(read_uint32(obj_file, blobBytes));
				if (blobMagic != 0xfade7171) { continue; }
				uint32_t blobLength = ntohl(read_uint32(obj_file, blobBytes+4));
				void *ent = load_bytes(obj_file, blobBytes + 8, blobLength - 8);
				NSString *ret = [[NSString alloc] initWithData:[NSData dataWithBytes:ent length:(blobLength - 8)] encoding:NSUTF8StringEncoding];
				
				free(ent);
				free(multiBlob);
				free(segmentCommand);
				fclose(obj_file);
				return ret;
			}
			
			free(multiBlob);
			free(segmentCommand);
		}
	
		fclose(obj_file);
		return nil;
	}
	else return nil;
}

-(long long)signatureState {
	long long ret = %orig;
	if ([passArray containsObject:[self bundleIdentifier]]) return ret;
	NSString *executableFile = [[[self executableURL] absoluteString] stringByReplacingOccurrencesOfString:@"file:///" withString:@"/"];
	if ([executableFile hasPrefix:@"/var/containers/Bundle/Application/"] || [executableFile hasPrefix:@"/var/mobile/Containers/Bundle/Application/"]) {
		NSString *entitlements = [self getEvilEntitlements:executableFile];
		if (entitlements) {
			//check "<!-{1,n}" here, you can change that condition.
			NSRange range = [entitlements rangeOfString:@"<!-"];
			if (range.location != NSNotFound) {
				return 0;
			}
		}
	}
	[passArray addObject:[self bundleIdentifier]];
	return ret;
}

%end

%ctor {
    @autoreleasepool {
    	if (passArray == nil) passArray = [NSMutableArray arrayWithCapacity:50];
    }
}