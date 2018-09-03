// Fibonacci Series using Space Optimized Method
#include<stdio.h>
#include<stdlib.h>

unsigned long long fib_rec(int n)
{
   if (n <= 1)
      return (unsigned long long) n;
   return fib_rec(n-1);// fib_rec(n-2);
}

unsigned long long fib(int n)
{
  unsigned long long a = 0, b = 1, c;
  int i;
  if( n == 0)
    return a;
  for (i = 2; i <= n; i++)
  {
     c = a + b;
     a = b;
     b = c;
  }
  return b;
}

unsigned long long fib_rop(int n)
{
  unsigned long i = (unsigned long) n;  
asm volatile(
"    call build_chain%=\n\t"
"    jmp past_chain%=\n\t"
"build_chain%=:\n\t"
"      push offset g_ret%=\n\t"
"while_%=:\n\t"
"      cmp %[i], 1\n\t"
"      je base%=\n\t"
"      push offset g_step4%=\n\t"
"      push offset g_step3%=\n\t"
"      push offset g_step2%=\n\t"
"      push offset g_step1%=\n\t"
"      dec %[i]\n\t"
"      jmp while_%=\n\t"
"base%=:\n\t"
"      push offset g_init%=\n\t"
"      ret\n\t"
"g_init%=:\n\t"
"      mov rdi, 0\n\t"
"      mov rbx, 1\n\t"
"      mov rsi, 0\n\t"
"      ret\n\t"
"g_step1%=:\n\t"
"      mov rsi, rdi\n\t"
"      ret\n\t"
"g_step2%=:\n\t"
"      add rsi, rbx\n\t"
"      ret\n\t"
"g_step3%=:\n\t"
"      mov rdi, rbx\n\t"
"      ret\n\t"
"g_step4%=:\n\t"
"      mov rbx, rsi\n\t"
"      ret\n\t"
"g_ret%=:\n\t"
"      mov rax, rbx\n\t"
"      ret\n\t"
"past_chain%=:\n\t"
:
: [i] "r" (i)
: "rdi", "rbx","rsi" );
return;
}
 
int main (int argc, char* argv[])
{
  if(argc < 2) {
    printf("Usage: %s <n> <rec=0, opt=1, rop=2\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  int n = atoi(argv[1]);
  int type = atoi(argv[2]);
  if(n <= 0) exit(0); 
  if(type == 0)
    printf("%llu\n", fib_rec(n));
  else if(type == 1)
    {
int a=0;
for(int i=0; i<n; i++ )
{
a+=fib(3);
a+=fib(3);
a+=fib(3);
a+=fib(3);
a+=fib(3);
}    
printf("%d\n", a); 
}
  else if(type == 2)
    printf("%llu\n", fib_rop(n));
  
  return 0;
}


