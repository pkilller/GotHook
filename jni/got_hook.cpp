#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <android/log.h>
#include <linux/elf.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>

#define  LOG_TAG    "got_hook"
#define  logcat(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)

typedef unsigned char byte;
typedef unsigned int size_t;
size_t fread(void * __restrict, size_t, size_t, FILE * __restrict);

void* find_self_module();
void* find_module(const char *p_module_name);
bool set_hook(const char *psz_symbol, void *p_callback);

FILE* hookcallback_fopen(const char *, const char *)
{
	logcat("/*** hook callback ***/");
	return NULL;
}

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void *reserved)
{
	logcat("JNI_OnLoad()");
	//find_module("got_hook");
	set_hook("fopen", (void*)&hookcallback_fopen);

	fopen(0, 0);
	return JNI_VERSION_1_4;
}

void* find_self_module()
{
	byte *p = (byte*)find_self_module;
	p = (byte*)((unsigned int)p & 0xFFFFF000);
	byte elf_ident[] = {0x7F,0x45,0x4C,0x46};
	while(*(unsigned int*)p != *(unsigned int*)&elf_ident)
	{
		//logcat("cur: %p  *cur: %x", p, *(unsigned int*)p);
		p -= 0x1000;
	}
	//logcat("self base: %p", p);
	return (void*)p;
}

void* find_module(const char *psz_module_name)
{
	FILE *pf = fopen("/proc/self/maps", "r");
	char sz_line[0x500];
	while(0==feof(pf))
	{
		if ( fgets( sz_line, sizeof(sz_line), pf ) )
		{
			// logcat("read line:%s", sz_line);
			if ( strstr(sz_line, psz_module_name ) )
			{
				sz_line[8] = '\0';
				void *p = (void*)strtoul(sz_line, NULL, 16);
				//logcat("main base: %p", p);
				return p;
			}
		}
	}

	return NULL;
}

Elf32_Addr get_dynamic_table(void *p_medule_base)
{

	//logcat("get_dynamic_table step: 1");
	Elf32_Ehdr *p_header = (Elf32_Ehdr*)p_medule_base;
	Elf32_Phdr *p_program_header = (Elf32_Phdr*)( (unsigned int)p_medule_base + p_header->e_phoff );
	Elf32_Half program_header_count = p_header->e_phnum;
	Elf32_Addr dynamic_table_addr = NULL;
	//logcat("get_dynamic_table step: 2");
	for ( int i = 0; i < program_header_count; i++ )
	{
		//logcat("get_dynamic_table step: 3, dynamic: %p", p_program_header);
		if ( p_program_header[i].p_type == PT_DYNAMIC )
		{
			//logcat("get_dynamic_table step: 4");
			dynamic_table_addr = p_program_header[i].p_vaddr;
			//logcat( "DynTalbe:%p\r\n", dynamic_table_addr );
			return dynamic_table_addr;
		}
	}
	return NULL;
}

const char* get_inerp( const char *psz_module_name )
{
	void *pMainBase = find_module( psz_module_name );
	if ( pMainBase == NULL)
	{
		return NULL;
	}
	logcat("main base: %p", pMainBase);
	Elf32_Ehdr *p_header = (Elf32_Ehdr*)pMainBase;
	Elf32_Phdr *p_program_header = (Elf32_Phdr*)( (unsigned int)pMainBase + p_header->e_phoff );
	Elf32_Half program_header_count = p_header->e_phnum;

	for ( int i = 0; i < program_header_count; i++ )
	{
		if ( p_program_header[i].p_type == PT_INTERP )
		{
			return (const char*)p_program_header[i].p_vaddr;
		}
	}
	return NULL;
}

Elf32_Addr get_table_from_dynt(Elf32_Dyn *p_dynamic_table, Elf32_Sword tag)
{
	while ( p_dynamic_table->d_tag != 0 )
	{
		if ( p_dynamic_table->d_tag == tag )
		{
			return p_dynamic_table->d_un.d_ptr;
		}
		p_dynamic_table ++;
	}
	return NULL;
}

// ELF Hash Function
Elf32_Sword elf_hash(const char *str)
{
    unsigned int hash = 0;
    unsigned int x = 0;

    while (*str)
    {
        hash = (hash << 4) + (*str++);
        if ((x = hash & 0xF0000000L) != 0)
        {
            hash ^= (x >> 24);
            hash &= ~x;
        }
    }
    //返回一个符号位为0的数，即丢弃最高位，以免函数外产生影响。(我们可以考虑，如果只有字符，符号位不可能为负)
    return (hash & 0x7FFFFFFF);
}

Elf32_Word get_symbol_index(void *p_module_base, const char *psz_symbol)
{
	Elf32_Dyn *p_dynamic_table = (Elf32_Dyn*)((Elf32_Addr)p_module_base + get_dynamic_table( p_module_base ));

	// symbol table
	Elf32_Addr symbol_table_offset = get_table_from_dynt( p_dynamic_table, DT_SYMTAB );
	Elf32_Sym *p_symbol_table = (Elf32_Sym*)((Elf32_Addr)p_module_base + symbol_table_offset);
	//logcat("1");
	// str table
	Elf32_Addr str_table_offset_ = get_table_from_dynt( p_dynamic_table, DT_STRTAB );
	const char *p_str_table =  (const char*)((Elf32_Addr)p_module_base + str_table_offset_);
	//logcat("2");
	// hash table
	Elf32_Addr hash_table_offset = get_table_from_dynt( p_dynamic_table, DT_HASH );
	Elf32_Sword *p_hash_table = (Elf32_Sword*)((Elf32_Addr)p_module_base + hash_table_offset);
	Elf32_Sword hash_bucket_count = *( p_hash_table+0 );
	Elf32_Sword hash_chine_count = *( p_hash_table+1 );
	Elf32_Sword *p_hash_bucket = p_hash_table+2;
	Elf32_Sword *p_hash_chine = p_hash_table+2+hash_bucket_count;
	//logcat("3");
	//logcat( "hash_table: %d %d %p %p", hash_bucket_count, hash_chine_count, p_hash_bucket, p_hash_chine );


	Elf32_Sword symb_hash = elf_hash( psz_symbol );
	int hash_index = symb_hash % hash_bucket_count;
	int symb_index = p_hash_bucket[hash_index];
	Elf32_Addr str_table_offset = p_symbol_table[symb_index].st_name;
	const char *pcurstr = p_str_table + str_table_offset;
	bool is_hit = false;
	if (strcmp(pcurstr, psz_symbol) == 0)
	{
		//logcat("hit chine printf");
		is_hit = true;
	}
	else
	{
		// 未命中, 出现碰撞
		int chine_index = symb_index;
		while(chine_index < hash_chine_count && chine_index != 0)
		{
			symb_index = p_hash_chine[chine_index];
			str_table_offset = p_symbol_table[symb_index].st_name;
			pcurstr = p_str_table + str_table_offset;
			//logcat("str: %s", pcurstr);
			if ( strcmp(pcurstr, psz_symbol) == 0 )
			{
				//logcat("hit chine");
				is_hit = true;
				break;
			}
			chine_index = symb_index;
		}
	}
	if ( !is_hit )
	{
		return false;
	}
	// logcat("hit sym index: %d", symb_index);

	return symb_index;
}

void* g_tmp = (void*)fopen;

bool get_fun_addr_in_got( void *p_module_base,  Elf32_Word symbol_index, Elf32_Addr **pp_rel_got, Elf32_Addr **pp_jmprel_got )
{
	Elf32_Dyn *p_dynamic_table = (Elf32_Dyn*)((Elf32_Addr)p_module_base + get_dynamic_table( p_module_base ));

	// symbol table
	Elf32_Rel *rels = (Elf32_Rel*)((Elf32_Word)p_module_base + get_table_from_dynt( p_dynamic_table, DT_REL ));
	Elf32_Word relsz = get_table_from_dynt( p_dynamic_table, DT_RELSZ );

	Elf32_Rel *jmprels = (Elf32_Rel*)((Elf32_Word)p_module_base + get_table_from_dynt( p_dynamic_table, DT_JMPREL ));
	Elf32_Word jmprelsz = get_table_from_dynt( p_dynamic_table, DT_PLTRELSZ );

	// search rel
	int rel_count = relsz / sizeof(Elf32_Rel);
	for (int i = 0; i < rel_count; i++ )
	{
		Elf32_Word tmp_symbol_index = ELF32_R_SYM(rels[i].r_info);
		if (tmp_symbol_index == symbol_index)
		{
			*pp_rel_got = (Elf32_Addr*)((Elf32_Addr)p_module_base + rels[i].r_offset);
			logcat("hit rel item: %p", *pp_rel_got);
			break;
		}
	}

	// search jmprel
	int jmprel_count = jmprelsz / sizeof(Elf32_Rel);
	for (int i = 0; i < jmprel_count; i++ )
	{
		Elf32_Word tmp_symbol_index = ELF32_R_SYM(jmprels[i].r_info);
		if (tmp_symbol_index == symbol_index)
		{
			*pp_jmprel_got = (Elf32_Addr*)((Elf32_Addr)p_module_base + jmprels[i].r_offset);
			logcat("hit jmprel item: %p", *pp_jmprel_got);
			break;
		}
	}
	return *pp_rel_got || *pp_jmprel_got;

}


#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

bool set_hook(const char *psz_symbol, void *p_callback)
{
	char *psz_module = "libgot_hook.so";
	sleep(3);
	//"/system/bin/app_process"
	void *p_module_base = find_module( psz_module );
	if ( p_module_base == NULL)
	{
		return NULL;
	}

	logcat("module base: %p", p_module_base);

	Elf32_Word symbol_index = get_symbol_index(p_module_base, psz_symbol);

	Elf32_Addr *p_rel_got = NULL;
	Elf32_Addr *p_jmprel_got = NULL;
	get_fun_addr_in_got(p_module_base, symbol_index, &p_rel_got, &p_jmprel_got);

	logcat("rel_got: %p,  jmprel_got: %p", p_rel_got, p_jmprel_got);

	*p_rel_got = (Elf32_Addr)p_callback;
	*p_jmprel_got = (Elf32_Addr)p_callback;

	// 动态调用无法被拦截
	/*
	typedef  FILE*  (*fp_fopen)(const char *, const char *);
	fp_fopen my_fopen = (fp_fopen)dlsym(RTLD_DEFAULT, "fopen");
	logcat("my_fopen:%p", my_fopen);
	my_fopen( "myfile.dat", "r");*/

	logcat("set hook succeed~");
	return true;
}
