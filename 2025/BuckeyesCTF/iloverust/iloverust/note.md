The real index can be computed as:

```c
target == notes + (idx << 4)
```

So if we want to read from `environ_ptr`, we can rearrange this to find `idx`:

```
idx == (environ_ptr - notes) >> 4
```

Which gives us a big positive number, so that we can't pass the check. Overcome this by adding `0xf000000000000000` to `idx`, which will make it a large negative number in signed 64-bit representation, thus passing the check while still pointing to the desired address. Note that in unsigned 64-bit the `0xf000000000000000` will overflow to 0, so the effective index will still be `(environ_ptr - notes) >> 4`.
