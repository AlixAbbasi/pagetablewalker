//x86 32 bit page table walker. 
#define PPAGE_SIZE 0x1000
#define PENTRIES 0x200
#define PLEVEL_4_SHIFT 12
#define PLEVEL_3_SHIFT 21
#define PLEVEL_2_SHIFT 30
#define PLEVEL_1_SHIFT 39
#define SIGN_EXTEND_TRESHOLD 0x100
#define SIGN_EXTEND 0xFFFF000000000000ULL
#define PAGETABLE_MASK 0x1FFFFFFFFF000ULL
#define PML4_ENTRY_MASK 0x1FFFFFFFFF000ULL
#define PML3_ENTRY_MASK 0x1FFFFC0000000ULL
#define PML2_ENTRY_MASK 0x1FFFFFFE00000ULL

#define CHECK_BIT(var,pos) !!(((var) & (1ULL<<(pos))))




/* FIX ME */
static uint64_t get_48_paging_phys_addr(uint64_t cr3, uint64_t addr){
    //if(addr == 0x7ffff7f4e000){
        //fprintf(stderr, "GDB ME NOW\n");
        //while(true){}
    //    print_48_paging2(cr3);
    //}

    //fprintf(stderr, "CALLING: %s (%lx) %lx\n", __func__, cr3, addr);

    /* signedness broken af -> fix me! */
    uint16_t pml_4_index = (addr & 0xFF8000000000ULL) >> 39;
    uint16_t pml_3_index = (addr & 0x0007FC0000000UL) >> 30;
    uint16_t pml_2_index = (addr & 0x000003FE00000UL) >> 21;
    uint16_t pml_1_index = (addr & 0x00000001FF000UL) >> 12;

    //if(addr == 0x7ffff7f4e000){
    //    printf("pml_4_index: %lx\n", pml_4_index);
    //    printf("pml_3_index: %lx\n", pml_3_index);
    //    printf("pml_2_index: %lx\n", pml_2_index);
    //    printf("pml_1_index: %lx\n", pml_1_index);
    //
    //}

    uint64_t address_identifier_1, address_identifier_2, address_identifier_3, address_identifier_4;
    uint64_t paging_entries_buffer[PENTRIES];

//somewhere on QEMU 3.1.0 code base is cpu_physical_memory_rw function.
// we can use this function to read or write memory. Here we are reading . void cpu_physical_memory_rw(hwaddr addr, uint8_t *buf, int len, int is_write)


    cpu_physical_memory_rw((cr3&PAGETABLE_MASK), (uint8_t *) paging_entries_buffer, PPAGE_SIZE, false);
    if(paging_entries_buffer[pml_4_index]){
        address_identifier_4 = ((uint64_t)pml_4_index) << PLEVEL_1_SHIFT;
        if (pml_4_index & SIGN_EXTEND_TRESHOLD){
            address_identifier_4 |= SIGN_EXTEND;
        }
        if(CHECK_BIT(paging_entries_buffer[pml_4_index], 0)){ /* otherwise swapped out */ 
            cpu_physical_memory_rw((paging_entries_buffer[pml_4_index]&PAGETABLE_MASK), (uint8_t *) paging_entries_buffer, PPAGE_SIZE, false);
            if(paging_entries_buffer[pml_3_index]){

                address_identifier_3 = (((uint64_t)pml_3_index) << PLEVEL_2_SHIFT) + address_identifier_4;
                if (CHECK_BIT(paging_entries_buffer[pml_3_index], 0)){ /* otherwise swapped out */ 

                    if (CHECK_BIT(paging_entries_buffer[pml_3_index], 7)){
                        /* 1GB PAGE */
                        return (paging_entries_buffer[pml_3_index] & PML3_ENTRY_MASK) | (0x7FFFFFFF & addr); 
                    }
                    else{
                        cpu_physical_memory_rw((paging_entries_buffer[pml_3_index]&PAGETABLE_MASK), (uint8_t *) paging_entries_buffer, PPAGE_SIZE, false);
                        if(paging_entries_buffer[pml_2_index]){
                            address_identifier_2 = (((uint64_t)pml_2_index) << PLEVEL_3_SHIFT) + address_identifier_3;
                            if (CHECK_BIT(paging_entries_buffer[pml_2_index], 0)){ /* otherwise swapped out */ 
                                if (CHECK_BIT(paging_entries_buffer[pml_2_index], 7)){
                                    /* 2MB PAGE */
                                    return (paging_entries_buffer[pml_2_index] & PML2_ENTRY_MASK) | (0x3FFFFF & addr); 
                                }
                                else{
                                    cpu_physical_memory_rw((paging_entries_buffer[pml_2_index]&PAGETABLE_MASK), (uint8_t *) paging_entries_buffer, PPAGE_SIZE, false);
                                    if(paging_entries_buffer[pml_1_index]){
                                        address_identifier_1 = (((uint64_t)pml_1_index) << PLEVEL_4_SHIFT) + address_identifier_2;
                                        if (CHECK_BIT(paging_entries_buffer[pml_1_index], 0)){
                                            /* 4 KB PAGE */
                                            return (paging_entries_buffer[pml_1_index] & PML4_ENTRY_MASK) | (0xFFF & addr); 
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    //fprintf(stderr, "FAILED: %s %lx\n", __func__, addr);
    //qemu_backtrace();
    //print_48_paging2(cr3);
    return 0xFFFFFFFFFFFFFFFFULL; /* invalid */
