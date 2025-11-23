#include "heap.h"
#include <pthread.h>

#define MIN_size     ((size_t) (HeapStructSize << 1))

Class(heap_node)
{
    heap_node *next;
    size_t BlockSize;
};

Class(xheap)
{
    heap_node head;
    heap_node *tail;
    size_t AllSize;
};

xheap TheHeap = {
        .tail = NULL,
        .AllSize = config_heap,
};

static  uint8_t AllHeap[config_heap];
static const size_t HeapStructSize = (sizeof(heap_node) + (size_t)(alignment_byte)) &~(alignment_byte);



void heap_init( void )
{
    heap_node *first_node;
    uintptr_t start_heap ,end_heap;
    
    start_heap =(uintptr_t)AllHeap;
    if( (start_heap & alignment_byte) != 0){
        start_heap += alignment_byte ;
        start_heap &= ~alignment_byte;
        TheHeap.AllSize -=  (size_t)(start_heap - (uintptr_t)AllHeap);
    }
    TheHeap.head.next = (heap_node *)start_heap;
    TheHeap.head.BlockSize = (size_t)0;
    end_heap = start_heap + (uint32_t)TheHeap.AllSize - (uint32_t)HeapStructSize;
    if( (end_heap & alignment_byte) != 0){
        end_heap &= ~alignment_byte;
        TheHeap.AllSize =  (size_t)(end_heap - start_heap );
    }
    TheHeap.tail = (heap_node *)end_heap;
    TheHeap.tail->BlockSize  = 0;
    TheHeap.tail->next =NULL;
    first_node = (heap_node *)start_heap;
    first_node->next = TheHeap.tail;
    first_node->BlockSize = TheHeap.AllSize;
}

void *heap_malloc1(size_t WantSize)
{
    heap_node *prev_node;
    heap_node *use_node;
    heap_node *new_node;
    size_t alignment_require_size;
    void *xReturn = NULL;
    WantSize += HeapStructSize;
    if((WantSize & alignment_byte) != 0x00) {
        alignment_require_size = (alignment_byte + 1) - (WantSize & alignment_byte);
        WantSize += alignment_require_size;
    }
    if(TheHeap.tail== NULL ) {
        heap_init();
    }
    prev_node = &TheHeap.head;
    use_node = TheHeap.head.next;
    while((use_node->BlockSize) < WantSize) {
        prev_node = use_node;
        use_node = use_node->next;
        if(use_node == NULL){
            return xReturn;
        }
    }
    xReturn = (void*)( ( (uint8_t*)use_node ) + HeapStructSize );
    prev_node->next = use_node->next ;
    if( (use_node->BlockSize - WantSize) > MIN_size ) {
        new_node = (void *) (((uint8_t *) use_node) + WantSize);
        new_node->BlockSize = use_node->BlockSize - WantSize;
        use_node->BlockSize = WantSize;
        new_node->next = prev_node->next;
        prev_node->next = new_node;
    }
    TheHeap.AllSize-= use_node->BlockSize;
    use_node->next = NULL;
    return xReturn;
}

static void InsertFreeBlock(heap_node* xInsertBlock);
void heap_free1(void *xReturn)
{
    heap_node *xlink;
    uint8_t *xFree = (uint8_t*)xReturn;

    xFree -= HeapStructSize;
    xlink = (void*)xFree;
    TheHeap.AllSize += xlink->BlockSize;
    InsertFreeBlock((heap_node*)xlink);
}

static void InsertFreeBlock(heap_node* xInsertBlock)
{
    heap_node *first_fit_node;
    uint8_t* getaddr;

    for(first_fit_node = &TheHeap.head;first_fit_node->next < xInsertBlock;first_fit_node = first_fit_node->next)
    { }

    xInsertBlock->next = first_fit_node->next;
    first_fit_node->next = xInsertBlock;

    getaddr = (uint8_t*)xInsertBlock;
    if((getaddr + xInsertBlock->BlockSize) == (uint8_t*)(xInsertBlock->next)) {
        if (xInsertBlock->next != TheHeap.tail) {
            xInsertBlock->BlockSize += xInsertBlock->next->BlockSize;
            xInsertBlock->next = xInsertBlock->next->next;
        } else {
            xInsertBlock->next = TheHeap.tail;
        }
    }
    getaddr = (uint8_t*)first_fit_node;
    if((getaddr + first_fit_node->BlockSize) == (uint8_t*) xInsertBlock) {
        first_fit_node->BlockSize += xInsertBlock->BlockSize;
        first_fit_node->next = xInsertBlock->next;
    }
}





pthread_mutex_t alloc_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t free_lock = PTHREAD_MUTEX_INITIALIZER;

unsigned int alloc_count = 0;
unsigned int free_count = 0;

void *heap_malloc(size_t WantSize)
{
    pthread_mutex_lock(&alloc_lock);
    void *ret = heap_malloc1(WantSize);
    printf("alloc is: %p\n", ret);
    alloc_count++;
    pthread_mutex_unlock(&alloc_lock);

    return ret;
}


void heap_free(void *xReturn)
{
    pthread_mutex_lock(&free_lock);
    void **ptr = (void **)xReturn;
    if (*ptr) {
        printf("free is: %p\n", *ptr);
        heap_free1(*ptr);
        *ptr = NULL; 
    }
    free_count++;
    pthread_mutex_unlock(&free_lock);
}
