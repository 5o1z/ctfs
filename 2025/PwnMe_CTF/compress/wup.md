## Bug

```c
void __fastcall flate_string(const char *s, char *a2)
{
  int v2; // eax
  char v3; // [rsp+13h] [rbp-2Dh]
  int v4; // [rsp+14h] [rbp-2Ch]
  int count; // [rsp+18h] [rbp-28h]
  int print_char; // [rsp+1Ch] [rbp-24h]
  int i; // [rsp+20h] [rbp-20h]
  int j; // [rsp+24h] [rbp-1Ch]

  v4 = 0;
  count = 0;
  for ( i = 0; i < strlen(s); ++i )
  {
    if ( ((*__ctype_b_loc())[s[i]] & 0x800) != 0 )
    {
      print_char = 0;
      while ( ((*__ctype_b_loc())[s[i]] & 0x800) != 0 )
      {
        print_char = 10 * print_char + s[i] - '0';
        if ( count + print_char > 512 )
          return;
        ++i;
      }
      v3 = s[i];
      count += print_char;
      for ( j = 0; j < print_char; ++j )
      {
        v2 = v4++;
        a2[v2] = v3;
      }
    }
  }
  a2[v4] = 0;                                   // Can cause off-by-one bug since v4 can be 512 when it return
}
```

There are 2 bug here:
- The v4 can reach 512, and then a2[v4] = 0 will write out of bound by 1 byte.
- `a2` is uninitialized variable

Playing with these bugs, and reading the pseudo code, we can also see that the function will return immediately when the count exceed 512. We can take advantage of this to leak every address in `a2`

## Exploit idea

- Leak heap, stack, libc base, exe base via uninitialized variable read
- Unsortedbin poisoning via off-by-one to get arbitrary write (I have note all step by step in the exploit code)
- Overwrite return address on stack to get shell

## Unsortedbin poisoning explanation

The heap layout we will setup like this:

```sh
chunk1 -> size = 0x3f0
chunk1 -> fd = main_arena
chunk1 -> bk = target

target -> size = 0x420
target -> fd = chunk1
target -> bk = chunk2

chunk2 -> size = ? (anything >= 0x20 (doesnt matter))
chunk2 -> fd = target
chunk2 -> bk = ? (anything (doesnt matter))

all the chunks must pass the adjacent's chunk check (size and prev_size)
```

And we must pass this migiration check:

```c
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
```

Let's see how it works:

When we allocate a chunk with size 0x420, the malloc first looks into `main_arena`'s unsortedbin list, at this time, the `unsorted_chunks(av)` is `chunk1`, so the `victim` is `chunk1`.

Then it checks if `bck->fd == victim`, which is `target->fd == chunk1`, it's true.

Then it checks if `victim->fd == unsorted_chunks(av)`, which is `chunk1->fd == chunk1`, it's also true.

But the size of `chunk1` isn't match our request, so malloc will remove `chunk1` from unsortedbin, and insert it into smallbin, this time malloc will update:

```sh
target->fd = main_arena+96
target->bk = chunk2 (not changed)
```

That function is doing by:

```c
          /* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);
```

And then continue checking `target` chunk, which is now match our request size, so malloc will return `target` chunk to us.
