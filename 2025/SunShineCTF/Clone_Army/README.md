## Clone Army - SunshineCTF 2025

The vulnerability is in this function `make_clones`, which is in an infinite loop until you request to break out of it. it asks for a number, adds that to the global `clone_army_count`, resizes the heap allocation at clone_army to that value, then "makes clones" (basically just writes data you control) for every index between what clone_army_count was before and the new `clone_army_count`. so if you supply 5 on the first loop and 10 on the second loop, on the second loop it'll only write to `clone_army[5]` through `clone_army[10]` because the first loop already wrote up to `clone_army[4]`.

The bug there is that it doesn't check if `realloc()` returns NULL, which you can do by asking to allocate more memory than your computer has. So if you supply 5 on the first loop and `2147483647` on the second loop, it'll try writing to `0[5] through 0[2147483647]`.

```c
      clone_army = realloc(clone_army, 16LL * (unsigned int)::clone_army_count);// VULN: return NULL if we allocate a big size
      for ( i = clone_army_count; i < ::clone_army_count; ++i )
      {
        ptr = (char *)clone_army + 16 * i;      // then this will write to &0[clone_army_count]
                                                // PIE is off -> so this will be arbitrary write
                                                // example:
                                                //         send 263068 (&GOT // 16)
                                                //         then send overflow_number (2147483647)
        *ptr = 16 * i;
        ptr[1] = master_height;
        ptr[2] = master_weight;
        ptr[3] = master_accuracy;
      }
```

But trying to write to `0[5]` is going to just immediately crash, but we can turn this into an arbitrary write because we can pick any number we want there. so, if we supply the address of `BSS` (pie is off) on the first loop, and `2147483647` on the second loop, it'll start trying to write to `0[exe.bss()] through 0[2147483647]`

So now we have some control over BSS, but this is still going to crash as-is because that loop is going to write to every memory address between `exe.bss() and 2147483647`, and about 99% of that is unmapped memory meaning we'd segfault. We can get around this, because the thing that determines whether the loop will stop is already in BSS. so, if we use this loop to write 0 to `clone_army_count`, we'll immediately exit out and won't crash anymore
