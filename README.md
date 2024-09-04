## Sample output
  
***** local_file_header *****  
local_file_header_signature = (50 4b 03 04)  
version_needed_to_extract = (0a 00)  
general_purpose_bit_flag = (09 00)  
        Bit 0: encrypted file = 1  
        Bit 3: data descriptor = 1  
compression_method = 99 (63 00)  
last_mod_file_time = (01 90)  
last_mod_file_date = (24 59)  
crc_32 = (00 00 00 00)  
compressed_size = 33 (21 00 00 00)  
uncompressed_size = 5 (05 00 00 00)  
file_name_length = 7 (07 00)  
extra_field_length = 11 (0b 00)  
file_name = "123.txt"  
extra_field = (01 99 07 00 02 00 41 45 03 00 00)  
        encrypt_header = (01 99)  
        encrypt_data_size = (07 00)  
        encrypt_data = (02 00 41 45 03 00 00)  
  
file_data =  
(5f ac 12 cc 83 83 12 6e 29 d9 19 4d 21 93 03 49)  
...  
(44 a6 d4 5e 96 44 a7 35 7c f6 87 5b 9c 9d 92 fc)  
***** Data descriptor *****  
signature = (50 4b 07 08)  
crc_32 = (00 00 00 00)  
compressed_size = 33 (21 00 00 00)  
uncompressed_size = 5 (05 00 00 00)  
  
  
***** Central directory header *****  
central_file_header_signature = (50 4b 01 02)  
version_made_by = (1f 00)  
version_needed_to_extract = (0a 00)  
general_purpose_bit_flag = (09 00)  
Bit 0: encrypted file = 1  
Bit 3: data descriptor = 1  
compression_method = (63 00)  
last_mod_file_time = (01 90)  
last_mod_file_date = (24 59)  
crc_32 = (00 00 00 00)  
compressed_size = (21 00 00 00)  
uncompressed_size = (05 00 00 00)  
file_name_length = (07 00)  
extra_field_length = (2f 00)  
file_comment_length = (00 00)  
disk_number_start = (00 00)  
internal_file_attributes = (00 00)  
external_file_attributes = (20 00 00 00)  
relative_offset_of_local_header = (00 00 00 00)  
file_name = "123.txt"  
extra_field = (0a 00 20 00 00 00 00 00 01 00 18 00 c7 15 69 bd d2 fe da 01 c7 15 69 bd d2 fe da 01 20 f0 0a ba d2 fe da 01 01 99 07 00 02 00 41 45 03 00 00)  
file_comment = null ()  
  
  
***** End of central directory record *****  
end_of_central_dir_signature = (50 4b 05 06)  
number_of_this_disk = (00 00)  
number_of_the_disk_with_the_start_of_the_central_directory = (00 00)  
total_number_of_entries_in_the_central_directory_on_this_disk = (01 00)  
total_number_of_entries_in_the_central_directory = (01 00)  
size_of_the_central_directory = (64 00 00 00)  
offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number = (61 00 00 00)  
ZIP_file_comment_length = (00 00)  
ZIP_file_comment = ()  
