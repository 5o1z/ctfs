void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int extra_len; // [rsp+0h] [rbp-50h]
  unsigned int pos1; // [rsp+8h] [rbp-48h]
  unsigned int pos2; // [rsp+8h] [rbp-48h]
  unsigned int pos3; // [rsp+8h] [rbp-48h]
  unsigned int n0x10_3; // [rsp+8h] [rbp-48h]
  int size; // [rsp+Ch] [rbp-44h]
  void (__fastcall __noreturn *buf)(int, char **, char **); // [rsp+10h] [rbp-40h] BYREF
  char *limit; // [rsp+18h] [rbp-38h]
  char *limit_2; // [rsp+20h] [rbp-30h]
  char *limit_1; // [rsp+28h] [rbp-28h]
  char choice[32]; // [rsp+30h] [rbp-20h] BYREF

  *(_QWORD *)&choice[24] = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  write(1, "Hello, colonists!\n", 0x12uLL);
  write(1, "Aliens are invading your planet colony!\n", 0x28uLL);
  write(1, "Actions have to be taken to defend your colony!\n", 0x30uLL);
  write(1, "You can control up to 16 weapons at the same time, each with a capacity of 1280 ammo!\n", 0x56uLL);
  limit = (char *)sbrk(0LL);
  limit_2 = limit + 135168;
  limit_1 = 0LL;
  extra_len = 0;
  buf = 0LL;
  memset(choice, 0, 24);
  while ( 1 )
  {
    write(1, "\n", 1uLL);
    write(1, "Make a choice:\n", 0xFuLL);
    write(1, "1. Build Weapon\n", 0x10uLL);
    write(1, "2. Launch Weapon\n", 0x11uLL);
    write(1, "3. Load Weapon\n", 0xFuLL);
    write(1, "4. Check Weapon\n", 0x10uLL);
    write(1, "5. Upgrade Weapon\n", 0x12uLL);
    write(1, "6. Detonate Bomb\n", 0x11uLL);
    write(1, ">> ", 3uLL);
    read(0, &choice[16], 7uLL);
    switch ( atoi(&choice[16]) )
    {
      case 1:
        write(1, "build weapon at position: ", 0x1AuLL);
        read(0, choice, 7uLL);
        pos1 = atoi(choice);
        if ( pos1 >= 0x10 )
          goto LABEL_18;
        write(1, "with capacity of: ", 0x12uLL);
        read(0, &choice[8], 7uLL);
        size = atoi(&choice[8]);
        if ( (unsigned int)size <= 0x500 )
        {
          limit_1 = (char *)malloc(size);
          if ( limit_1 >= limit && limit_2 >= limit_1 )
          {
            chunk[pos1] = limit_1;
            chunk_size[pos1] = size;
            write(1, "Weapon built successfully!\n", 0x1BuLL);
          }
          else
          {
            write(1, "You cannot build weapon outside of colony!\n", 0x2BuLL);
          }
        }
        else
        {
          write(1, "Invalid weapon capacity!\n", 0x19uLL);
        }
        continue;
      case 2:
        write(1, "launch weapon at position: ", 0x1BuLL);
        read(0, choice, 7uLL);
        pos2 = atoi(choice);
        if ( pos2 >= 0x10 )
          goto LABEL_18;
        if ( !chunk[pos2] )
          goto LABEL_20;
        free(chunk[pos2]);                      // uaf
        write(1, "Weapon launched successfully!\n", 0x1EuLL);
        break;
      case 3:
        write(1, "load weapon at position: ", 0x19uLL);
        read(0, choice, 7uLL);
        pos3 = atoi(choice);
        if ( pos3 >= 0x10 )
          goto LABEL_18;
        if ( !chunk[pos3] )
          goto LABEL_20;
        write(1, "with ammo of: ", 0xEuLL);
        read(0, chunk[pos3], chunk_size[pos3] + extra_len);
        write(1, "Weapon loaded successfully!\n", 0x1CuLL);
        break;
      case 4:
        write(1, "check weapon at position: ", 0x1AuLL);
        read(0, choice, 7uLL);
        n0x10_3 = atoi(choice);
        if ( n0x10_3 < 0x10 )
        {
          if ( chunk[n0x10_3] )
            write(1, chunk[n0x10_3], chunk_size[n0x10_3] + extra_len);
          else
LABEL_20:
            write(1, "No weapon at this position!\n", 0x1CuLL);
        }
        else
        {
LABEL_18:
          write(1, "Invalid weapon position!\n", 0x19uLL);
        }
        break;
      case 5:
        if ( buf )
        {
          write(1, "You can only upgrade weapon once!\n", 0x22uLL);
        }
        else
        {
          write(1, "upgrade weapon with resource: ", 0x1EuLL);
          read(0, &buf, 8uLL);
          if ( buf == main )
          {
            write(1, "You upgraded weapon successfully to a lethal level with extra ammo!\n", 0x44uLL);
            extra_len = 8;
          }
          else
          {
            write(1, "You have to find necessary resource to upgrade weapon!\n", 0x37uLL);
            extra_len = 0;
          }
          buf = 0LL;
        }
        continue;
      case 6:
        write(1, "A suicide bomb has been activated!\n", 0x23uLL);
        write(1, "Aliens were wiped out along with your colony!\n", 0x2EuLL);
        exit(0);
      default:
        write(1, "Noooooooo you made a bad choice!\n", 0x21uLL);
        write(1, "Aliens have successfully invaded your colony!\n", 0x2EuLL);
        exit(1);
    }
  }
}
