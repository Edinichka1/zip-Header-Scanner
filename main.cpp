#include <iostream>
#include <fstream>
#include <vector>

class zip
{
private:
    static unsigned long long getDec(char *header, unsigned char len)
    {
        unsigned long long result = 0;
        for (unsigned long long i = 0; i < len; ++i)
        {
            unsigned long long tmp = (header[i] < 0) ? (255 + header[i] + 1) : (header[i]);
            tmp <<= i * 8;
            result |= tmp;
        }
        return result;
    }
    static void read(std::ifstream &inf, char *header, unsigned long long len)
    {
        inf.read(header, len);
        if (inf.fail())
        {
            std::cout << "error on read" << std::endl;
            system("pause");
            exit(1);
        }
    }
    static void printHex(char *header, unsigned long long len)
    {
        const char *str = "0123456789abcdef";
        std::cout << '(';
        for (unsigned char i = 0; i < len; ++i)
        {
            unsigned char tmp = header[i];
            std::cout << str[tmp / 16] << str[tmp % 16] << ' ';
        }
        if (len)
        {
            std::cout << '\b';
        }
        std::cout << ')';
    }
    static void printText(char *header, unsigned long long len)
    {
        if (len)
        {
            std::cout << '"';
            for (unsigned long long i = 0; i < len; ++i)
            {
                std::cout << header[i];
            }
            std::cout << '"';
        }
        else
        {
            std::cout << "null";
        }
    }
    static void printHexText(char *header, unsigned long long len)
    {
        if (len)
        {
            std::cout << std::endl;
            if (len > 16)
            {
                printHex(header, 16);
                std::cout << std::endl;
                if (len > 32)
                {
                    std::cout << "..." << std::endl;
                }
                printHex(header + len - 16, 16);
            }
            else
            {
                printHex(header, len);
            }
        }
        else
        {
            std::cout << "null";
        }
    }

private:
    const char *path;
    std::ifstream inf;
    bool skip_files = 0;

    struct local_file_header
    {
        bool inited = 0;
        bool zip64 = 0;
        unsigned long long universal_compressed_size = 0;
        unsigned long long universal_uncompressed_size = 0;
        unsigned long long file_data_pos = 0;

        char local_file_header_signature[4];
        char version_needed_to_extract[2];
        char general_purpose_bit_flag[2];
        char compression_method[2];
        char last_mod_file_time[2];
        char last_mod_file_date[2];
        char crc_32[4];
        char compressed_size[4];
        char uncompressed_size[4];
        char file_name_length[2];
        char extra_field_length[2];

        char *file_name;
        char *extra_field;

        char encrypt_header[2];
        char encrypt_data_size[2];
        char *encrypt_data;

        struct extensible_data_field
        {
            char Tag_for_this_extra_block_type[2];
            char Size_of_this_extra_block[2];
            char *data;
        };
        std::vector<extensible_data_field> vecEDF;

        void print()
        {
            std::cout << "***** local_file_header *****" << std::endl;
            std::cout << "local_file_header_signature = ";
            printHex(local_file_header_signature, 4);
            std::cout << std::endl;
            std::cout << "version_needed_to_extract = ";
            printHex(version_needed_to_extract, 2);
            std::cout << std::endl;
            std::cout << "general_purpose_bit_flag = ";
            printHex(general_purpose_bit_flag, 2);
            if ((bool)(general_purpose_bit_flag[0] & 0b00000001))
            {
                std::cout << std::endl
                          << "\tBit 0: encrypted file = " << (bool)(general_purpose_bit_flag[0] & 0b00000001);
            }
            if ((bool)(general_purpose_bit_flag[0] & 0b00000010))
            {
                std::cout << std::endl
                          << "\tBit 1: compression option = " << (bool)(general_purpose_bit_flag[0] & 0b00000010);
            }
            if ((bool)(general_purpose_bit_flag[0] & 0b00000100))
            {
                std::cout << std::endl
                          << "\tBit 2: compression option = " << (bool)(general_purpose_bit_flag[0] & 0b00000100);
            }
            if ((bool)(general_purpose_bit_flag[0] & 0b00001000))
            {
                std::cout << std::endl
                          << "\tBit 3: data descriptor = " << (bool)(general_purpose_bit_flag[0] & 0b00001000);
            }
            if ((bool)(general_purpose_bit_flag[0] & 0b00010000))
            {
                std::cout << std::endl
                          << "\tBit 4: enhanced deflation = " << (bool)(general_purpose_bit_flag[0] & 0b00010000);
            }
            if ((bool)(general_purpose_bit_flag[0] & 0b00100000))
            {
                std::cout << std::endl
                          << "\tBit 5: compressed patched data = " << (bool)(general_purpose_bit_flag[0] & 0b00100000);
            }
            if ((bool)(general_purpose_bit_flag[0] & 0b01000000))
            {
                std::cout << std::endl
                          << "\tBit 6: strong encryption = " << (bool)(general_purpose_bit_flag[0] & 0b01000000);
            }
            if ((bool)(general_purpose_bit_flag[0] & 0b10000000))
            {
                std::cout << std::endl
                          << "\tBit 7: unused = " << (bool)(general_purpose_bit_flag[0] & 0b10000000);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b00000001))
            {
                std::cout << std::endl
                          << "\tBit 8: unused = " << (bool)(general_purpose_bit_flag[1] & 0b00000001);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b00000010))
            {
                std::cout << std::endl
                          << "\tBit 9: unused = " << (bool)(general_purpose_bit_flag[1] & 0b00000010);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b00000100))
            {
                std::cout << std::endl
                          << "\tBit 10: unused  = " << (bool)(general_purpose_bit_flag[1] & 0b00000100);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b00001000))
            {
                std::cout << std::endl
                          << "\tBit 11: language encoding = " << (bool)(general_purpose_bit_flag[1] & 0b00001000);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b00010000))
            {
                std::cout << std::endl
                          << "\tBit 12: reserved = " << (bool)(general_purpose_bit_flag[1] & 0b00010000);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b00100000))
            {
                std::cout << std::endl
                          << "\tBit 13: mask header values = " << (bool)(general_purpose_bit_flag[1] & 0b00100000);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b01000000))
            {
                std::cout << std::endl
                          << "\tBit 14: reserved = " << (bool)(general_purpose_bit_flag[1] & 0b01000000);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b10000000))
            {
                std::cout << std::endl
                          << "\tBit 15: reserved = " << (bool)(general_purpose_bit_flag[1] & 0b10000000);
            }
            std::cout << std::endl;
            std::cout << "compression_method = " << getDec(compression_method, 2) << ' ';
            printHex(compression_method, 2);
            std::cout << std::endl;
            std::cout << "last_mod_file_time = ";
            printHex(last_mod_file_time, 2);
            std::cout << std::endl;
            std::cout << "last_mod_file_date = ";
            printHex(last_mod_file_date, 2);
            std::cout << std::endl;
            std::cout << "crc_32 = ";
            printHex(crc_32, 4);
            std::cout << std::endl;
            std::cout << "compressed_size = " << getDec(compressed_size, 4) << ' ';
            printHex(compressed_size, 4);
            std::cout << std::endl;
            std::cout << "uncompressed_size = " << getDec(uncompressed_size, 4) << ' ';
            printHex(uncompressed_size, 4);
            std::cout << std::endl;
            std::cout << "file_name_length = " << getDec(file_name_length, 2) << ' ';
            printHex(file_name_length, 2);
            std::cout << std::endl;
            std::cout << "extra_field_length = " << getDec(extra_field_length, 2) << ' ';
            printHex(extra_field_length, 2);
            std::cout << std::endl;

            std::cout << "file_name = ";
            printText(file_name, getDec(file_name_length, 2));
            std::cout << std::endl;
            std::cout << "extra_field = ";
            printHex(extra_field, getDec(extra_field_length, 2));
            std::cout << std::endl;

            if ((bool)(general_purpose_bit_flag[0] & 0b00000001))
            {
                std::cout << "\tencrypt_header = ";
                printHex(encrypt_header, 2);
                std::cout << std::endl;
                std::cout << "\tencrypt_data_size = ";
                printHex(encrypt_data_size, 2);
                std::cout << std::endl;
                std::cout << "\tencrypt_data = ";
                printHex(encrypt_data, getDec(encrypt_data_size, 2));
                std::cout << std::endl
                          << std::endl;
            }
            for (unsigned long long i = 0; i < vecEDF.size(); ++i)
            {
                std::cout << "\tTag_for_this_extra_block_type = ";
                printHex(vecEDF[i].Tag_for_this_extra_block_type, 2);
                std::cout << std::endl;
                std::cout << "\tSize_of_this_extra_block = ";
                printHex(vecEDF[i].Size_of_this_extra_block, 2);
                std::cout << std::endl;
                std::cout << "\tdata = ";
                printHex(vecEDF[i].data, getDec(vecEDF[i].Size_of_this_extra_block, 2));
                std::cout << std::endl
                          << std::endl;
            }

            if ((unsigned char)(uncompressed_size[0]) == 0xff && (unsigned char)(uncompressed_size[1]) == 0xff)
            {
                std::cout << "\tuniversal_uncompressed_size_zip64 = " << universal_uncompressed_size << std::endl;
            }
            if ((unsigned char)(compressed_size[0]) == 0xff && (unsigned char)(compressed_size[1]) == 0xff)
            {
                std::cout << "\tuniversal_compressed_size_zip64 = " << universal_compressed_size << std::endl;
            }
        }
        void init(std::ifstream &inf)
        {
            read(inf, local_file_header_signature, 4);
            read(inf, version_needed_to_extract, 2);
            read(inf, general_purpose_bit_flag, 2);
            read(inf, compression_method, 2);
            read(inf, last_mod_file_time, 2);
            read(inf, last_mod_file_date, 2);
            read(inf, crc_32, 4);

            read(inf, compressed_size, 4);
            read(inf, uncompressed_size, 4);

            universal_uncompressed_size = getDec(uncompressed_size, 4);
            universal_compressed_size = getDec(compressed_size, 4);

            read(inf, file_name_length, 2);
            read(inf, extra_field_length, 2);

            file_name = new char[getDec(file_name_length, 2)];
            read(inf, file_name, getDec(file_name_length, 2));

            extra_field = new char[getDec(extra_field_length, 2)];
            read(inf, extra_field, getDec(extra_field_length, 2));

            inf.seekg(-(long long)getDec(extra_field_length, 2), std::ios_base::cur);
            unsigned long long extra_field_length_tmp = getDec(extra_field_length, 2);

            if ((bool)(general_purpose_bit_flag[0] & 0b00000001))
            {
                // encrypt
                read(inf, encrypt_header, 2);
                read(inf, encrypt_data_size, 2);

                encrypt_data = new char[getDec(encrypt_data_size, 2)];
                read(inf, encrypt_data, getDec(encrypt_data_size, 2));

                extra_field_length_tmp -= 2 + 2 + getDec(encrypt_data_size, 2);
            }
            if (extra_field_length_tmp)
            {
                zip64 = 1;
            }
            while (extra_field_length_tmp)
            {
                // zip64
                extensible_data_field edf;

                read(inf, edf.Tag_for_this_extra_block_type, 2);
                read(inf, edf.Size_of_this_extra_block, 2);

                edf.data = new char[getDec(edf.Size_of_this_extra_block, 2)];
                read(inf, edf.data, getDec(edf.Size_of_this_extra_block, 2));

                // save
                vecEDF.push_back(edf);
                extra_field_length_tmp -= 2 + 2 + getDec(edf.Size_of_this_extra_block, 2);
            }

            for (unsigned long long i = 0; i < vecEDF.size(); ++i)
            {

                switch (getDec(vecEDF[i].Tag_for_this_extra_block_type, 2))
                {
                case 0x0001:
                    universal_uncompressed_size = getDec(&vecEDF[i].data[0], 8);
                    universal_compressed_size = getDec(&vecEDF[i].data[8], 8);

                default:
                    break;
                }
            }
            file_data_pos = inf.tellg();

            inited = 1;
        }
    };

    struct encryption_header
    {
        bool inited = 0;
    };

    struct data_descriptor
    {
        bool inited = 0;
        bool zip64 = 0;
        bool signatureF = 0;
        char signature[4];
        char crc_32[4];
        char compressed_size[4];
        char uncompressed_size[4];

        char compressed_size_zip64[8];
        char uncompressed_size_zip64[8];

        void print()
        {
            std::cout << "***** Data descriptor *****" << std::endl;
            if (signatureF)
            {
                std::cout << "signature = ";
                printHex(signature, 4);
                std::cout << std::endl;
            }
            std::cout << "crc_32 = ";
            printHex(crc_32, 4);
            std::cout << std::endl;

            if (zip64)
            {
                std::cout << "compressed_size = " << getDec(compressed_size_zip64, 8) << ' ';
                printHex(compressed_size_zip64, 8);
                std::cout << std::endl;
                std::cout << "uncompressed_size = " << getDec(uncompressed_size_zip64, 8) << ' ';
                printHex(uncompressed_size_zip64, 8);
                std::cout << std::endl;
            }
            else
            {
                std::cout << "compressed_size = " << getDec(compressed_size, 4) << ' ';
                printHex(compressed_size, 4);
                std::cout << std::endl;
                std::cout << "uncompressed_size = " << getDec(uncompressed_size, 4) << ' ';
                printHex(uncompressed_size, 4);
                std::cout << std::endl;
            }
        }
        void init(std::ifstream &inf, bool zip64_l = 0)
        {
            char checker[4];
            read(inf, checker, 4);
            inf.seekg(-4, std::ios_base::cur);

            if (checker[0] == 0x50 && checker[1] == 0x4b && checker[2] == 0x07 && checker[3] == 0x08)
            {
                read(inf, signature, 4);
                signatureF = 1;
            }
            read(inf, crc_32, 4);
            if (zip64_l)
            {
                zip64 = 1;
                read(inf, compressed_size_zip64, 8);
                read(inf, uncompressed_size_zip64, 8);
            }
            else
            {
                read(inf, compressed_size, 4);
                read(inf, uncompressed_size, 4);
            }

            inited = 1;
        }
    };

    struct lefd
    {
        local_file_header local_file_h;
        encryption_header encryption_h;
        char *file_data = nullptr;
        data_descriptor data_descript;
    };

    struct archive_decryption_header
    {
        bool inited = 0;
    };

    struct archive_extra_data_record
    {
        bool inited = 0;
        char archive_extra_data_signature[4];
        char extra_field_length[4];
        char *extra_field_data;

        void print()
        {
            std::cout << "***** Archive extra data record *****" << std::endl;
            std::cout << "archive_extra_data_signature = ";
            printHex(archive_extra_data_signature, 4);
            std::cout << std::endl;
            std::cout << "extra_field_length = ";
            printHex(extra_field_length, 4);
            std::cout << std::endl;
            std::cout << "extra_field_data = ";
            printHexText(extra_field_data, getDec(extra_field_length, 4));
            std::cout << std::endl;
        }
        void init(std::ifstream &inf)
        {
            read(inf, archive_extra_data_signature, 4);
            read(inf, extra_field_length, 4);

            extra_field_data = new char[getDec(extra_field_length, 4)];
            read(inf, extra_field_data, getDec(extra_field_length, 4));

            inited = 1;
        }
    };

    struct central_directory_header
    {
        bool inited = 0;
        char central_file_header_signature[4];
        char version_made_by[2];
        char version_needed_to_extract[2];
        char general_purpose_bit_flag[2];
        char compression_method[2];
        char last_mod_file_time[2];
        char last_mod_file_date[2];
        char crc_32[4];
        char compressed_size[4];
        char uncompressed_size[4];
        char file_name_length[2];
        char extra_field_length[2];
        char file_comment_length[2];
        char disk_number_start[2];
        char internal_file_attributes[2];
        char external_file_attributes[4];
        char relative_offset_of_local_header[4];

        char *file_name;
        char *extra_field;
        char *file_comment;

        void print()
        {
            std::cout << "***** Central directory header *****" << std::endl;
            std::cout << "central_file_header_signature = ";
            printHex(central_file_header_signature, 4);
            std::cout << std::endl;
            std::cout << "version_made_by = ";
            printHex(version_made_by, 2);
            std::cout << std::endl;
            std::cout << "version_needed_to_extract = ";
            printHex(version_needed_to_extract, 2);
            std::cout << std::endl;
            std::cout << "general_purpose_bit_flag = ";
            printHex(general_purpose_bit_flag, 2);
            if ((bool)(general_purpose_bit_flag[0] & 0b00000001))
            {
                std::cout << std::endl
                          << "Bit 0: encrypted file = " << (bool)(general_purpose_bit_flag[0] & 0b00000001);
            }
            if ((bool)(general_purpose_bit_flag[0] & 0b00000010))
            {
                std::cout << std::endl
                          << "Bit 1: compression option = " << (bool)(general_purpose_bit_flag[0] & 0b00000010);
            }
            if ((bool)(general_purpose_bit_flag[0] & 0b00000100))
            {
                std::cout << std::endl
                          << "Bit 2: compression option = " << (bool)(general_purpose_bit_flag[0] & 0b00000100);
            }
            if ((bool)(general_purpose_bit_flag[0] & 0b00001000))
            {
                std::cout << std::endl
                          << "Bit 3: data descriptor = " << (bool)(general_purpose_bit_flag[0] & 0b00001000);
            }
            if ((bool)(general_purpose_bit_flag[0] & 0b00010000))
            {
                std::cout << std::endl
                          << "Bit 4: enhanced deflation = " << (bool)(general_purpose_bit_flag[0] & 0b00010000);
            }
            if ((bool)(general_purpose_bit_flag[0] & 0b00100000))
            {
                std::cout << std::endl
                          << "Bit 5: compressed patched data = " << (bool)(general_purpose_bit_flag[0] & 0b00100000);
            }
            if ((bool)(general_purpose_bit_flag[0] & 0b01000000))
            {
                std::cout << std::endl
                          << "Bit 6: strong encryption = " << (bool)(general_purpose_bit_flag[0] & 0b01000000);
            }
            if ((bool)(general_purpose_bit_flag[0] & 0b10000000))
            {
                std::cout << std::endl
                          << "Bit 7: unused = " << (bool)(general_purpose_bit_flag[0] & 0b10000000);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b00000001))
            {
                std::cout << std::endl
                          << "Bit 8: unused = " << (bool)(general_purpose_bit_flag[1] & 0b00000001);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b00000010))
            {
                std::cout << std::endl
                          << "Bit 9: unused = " << (bool)(general_purpose_bit_flag[1] & 0b00000010);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b00000100))
            {
                std::cout << std::endl
                          << "Bit 10: unused  = " << (bool)(general_purpose_bit_flag[1] & 0b00000100);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b00001000))
            {
                std::cout << std::endl
                          << "Bit 11: language encoding = " << (bool)(general_purpose_bit_flag[1] & 0b00001000);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b00010000))
            {
                std::cout << std::endl
                          << "Bit 12: reserved = " << (bool)(general_purpose_bit_flag[1] & 0b00010000);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b00100000))
            {
                std::cout << std::endl
                          << "Bit 13: mask header values = " << (bool)(general_purpose_bit_flag[1] & 0b00100000);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b01000000))
            {
                std::cout << std::endl
                          << "Bit 14: reserved = " << (bool)(general_purpose_bit_flag[1] & 0b01000000);
            }
            if ((bool)(general_purpose_bit_flag[1] & 0b10000000))
            {
                std::cout << std::endl
                          << "Bit 15: reserved = " << (bool)(general_purpose_bit_flag[1] & 0b10000000);
            }
            std::cout << std::endl;
            std::cout << "compression_method = ";
            printHex(compression_method, 2);
            std::cout << std::endl;
            std::cout << "last_mod_file_time = ";
            printHex(last_mod_file_time, 2);
            std::cout << std::endl;
            std::cout << "last_mod_file_date = ";
            printHex(last_mod_file_date, 2);
            std::cout << std::endl;
            std::cout << "crc_32 = ";
            printHex(crc_32, 4);
            std::cout << std::endl;
            std::cout << "compressed_size = ";
            printHex(compressed_size, 4);
            std::cout << std::endl;
            std::cout << "uncompressed_size = ";
            printHex(uncompressed_size, 4);
            std::cout << std::endl;
            std::cout << "file_name_length = ";
            printHex(file_name_length, 2);
            std::cout << std::endl;
            std::cout << "extra_field_length = ";
            printHex(extra_field_length, 2);
            std::cout << std::endl;
            std::cout << "file_comment_length = ";
            printHex(file_comment_length, 2);
            std::cout << std::endl;
            std::cout << "disk_number_start = ";
            printHex(disk_number_start, 2);
            std::cout << std::endl;
            std::cout << "internal_file_attributes = ";
            printHex(internal_file_attributes, 2);
            std::cout << std::endl;
            std::cout << "external_file_attributes = ";
            printHex(external_file_attributes, 4);
            std::cout << std::endl;
            std::cout << "relative_offset_of_local_header = ";
            printHex(relative_offset_of_local_header, 4);
            std::cout << std::endl;

            std::cout << "file_name = ";
            printText(file_name, getDec(file_name_length, 2));
            std::cout << std::endl;
            std::cout << "extra_field = ";
            printHex(extra_field, getDec(extra_field_length, 2));
            std::cout << std::endl;
            std::cout << "file_comment = ";
            printText(file_comment, getDec(file_comment_length, 2));
            std::cout << ' ';
            printHex(file_comment, getDec(file_comment_length, 2));
            std::cout << std::endl;
        }
        void init(std::ifstream &inf)
        {
            read(inf, central_file_header_signature, 4);
            read(inf, version_made_by, 2);
            read(inf, version_needed_to_extract, 2);
            read(inf, general_purpose_bit_flag, 2);
            read(inf, compression_method, 2);
            read(inf, last_mod_file_time, 2);
            read(inf, last_mod_file_date, 2);
            read(inf, crc_32, 4);
            read(inf, compressed_size, 4);
            read(inf, uncompressed_size, 4);
            read(inf, file_name_length, 2);
            read(inf, extra_field_length, 2);
            read(inf, file_comment_length, 2);
            read(inf, disk_number_start, 2);
            read(inf, internal_file_attributes, 2);
            read(inf, external_file_attributes, 4);
            read(inf, relative_offset_of_local_header, 4);

            file_name = new char[getDec(file_name_length, 2)];
            read(inf, file_name, getDec(file_name_length, 2));

            extra_field = new char[getDec(extra_field_length, 2)];
            read(inf, extra_field, getDec(extra_field_length, 2));

            file_comment = new char[getDec(file_comment_length, 2)];
            read(inf, file_comment, getDec(file_comment_length, 2));

            inited = 1;
        }
    };

    struct zip64_end_of_central_directory_record
    {
        bool inited = 0;
        char zip64_end_of_central_dir_signature[4];
        char size_of_zip64_end_of_central_directory_record[8];
        char version_made_by[2];
        char version_needed_to_extract[2];
        char number_of_this_disk[4];
        char number_of_the_disk_with_the_start_of_the_central_directory[4];
        char total_number_of_entries_in_the_central_directory_on_this_disk[8];
        char total_number_of_entries_in_the_central_directory[8];
        char size_of_the_central_directory[8];
        char offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number[8];
        char *zip64_extensible_data_sector;

        void print()
        {
            std::cout << "***** Zip64 end of central directory record *****" << std::endl;
            std::cout << "zip64_end_of_central_dir_signature = ";
            printHex(zip64_end_of_central_dir_signature, 4);
            std::cout << std::endl;
            std::cout << "version_made_by = ";
            printHex(version_made_by, 2);
            std::cout << std::endl;
            std::cout << "version_needed_to_extract = ";
            printHex(version_needed_to_extract, 2);
            std::cout << std::endl;
            std::cout << "number_of_this_disk = ";
            printHex(number_of_this_disk, 4);
            std::cout << std::endl;
            std::cout << "number_of_the_disk_with_the_start_of_the_central_directory = ";
            printHex(number_of_the_disk_with_the_start_of_the_central_directory, 4);
            std::cout << std::endl;
            std::cout << "total_number_of_entries_in_the_central_directory_on_this_disk = ";
            printHex(total_number_of_entries_in_the_central_directory_on_this_disk, 8);
            std::cout << std::endl;
            std::cout << "total_number_of_entries_in_the_central_directory = ";
            printHex(total_number_of_entries_in_the_central_directory, 8);
            std::cout << std::endl;
            std::cout << "size_of_the_central_directory = ";
            printHex(size_of_the_central_directory, 8);
            std::cout << std::endl;
            std::cout << "offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number = ";
            printHex(offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number, 8);
            std::cout << std::endl;

            // std::cout << "zip64_extensible_data_sector = ";  printHex(zip64_extensible_data_sector, getDec(size_of_zip64_end_of_central_directory_record, 8)); std::cout << std::endl;
        }
        void init(std::ifstream &inf)
        {
            read(inf, zip64_end_of_central_dir_signature, 4);
            read(inf, size_of_zip64_end_of_central_directory_record, 8);
            read(inf, version_made_by, 2);
            read(inf, version_needed_to_extract, 2);
            read(inf, number_of_this_disk, 4);
            read(inf, number_of_the_disk_with_the_start_of_the_central_directory, 4);
            read(inf, total_number_of_entries_in_the_central_directory_on_this_disk, 8);
            read(inf, total_number_of_entries_in_the_central_directory, 8);
            read(inf, size_of_the_central_directory, 8);
            read(inf, offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number, 8);

            /*zip64_extensible_data_sector = new char[getDec(size_of_zip64_end_of_central_directory_record, 8)];
            read(inf, zip64_extensible_data_sector, getDec(size_of_zip64_end_of_central_directory_record, 8) - 12);*/

            inited = 1;
        }
    };

    struct zip64_end_of_central_directory_locator
    {
        bool inited = 0;
        char zip64_end_of_central_dir_locator_signature[4];
        char number_of_the_disk_with_the_start_of_the_zip64_end_of_central_directory[4];
        char relative_offset_of_the_zip64_end_of_central_directory_record[8];
        char total_number_of_disks[4];

        void print()
        {
            std::cout << "***** Zip64 end of central directory locator *****" << std::endl;
            std::cout << "zip64_end_of_central_dir_locator_signature = ";
            printHex(zip64_end_of_central_dir_locator_signature, 4);
            std::cout << std::endl;
            std::cout << "number_of_the_disk_with_the_start_of_the_zip64_end_of_central_directory = ";
            printHex(number_of_the_disk_with_the_start_of_the_zip64_end_of_central_directory, 4);
            std::cout << std::endl;
            std::cout << "relative_offset_of_the_zip64_end_of_central_directory_record = ";
            printHex(relative_offset_of_the_zip64_end_of_central_directory_record, 8);
            std::cout << std::endl;
            std::cout << "total_number_of_disks = ";
            printHex(total_number_of_disks, 4);
            std::cout << std::endl;
        }
        void init(std::ifstream &inf)
        {
            read(inf, zip64_end_of_central_dir_locator_signature, 4);
            read(inf, number_of_the_disk_with_the_start_of_the_zip64_end_of_central_directory, 4);
            read(inf, relative_offset_of_the_zip64_end_of_central_directory_record, 8);
            read(inf, total_number_of_disks, 4);

            inited = 1;
        }
    };

    struct end_of_central_directory_record
    {
        bool inited = 0;
        char end_of_central_dir_signature[4];
        char number_of_this_disk[2];
        char number_of_the_disk_with_the_start_of_the_central_directory[2];
        char total_number_of_entries_in_the_central_directory_on_this_disk[2];
        char total_number_of_entries_in_the_central_directory[2];
        char size_of_the_central_directory[4];
        char offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number[4];
        char ZIP_file_comment_length[2];
        char *ZIP_file_comment;

        void print()
        {
            std::cout << "***** End of central directory record *****" << std::endl;
            std::cout << "end_of_central_dir_signature = ";
            printHex(end_of_central_dir_signature, 4);
            std::cout << std::endl;
            std::cout << "number_of_this_disk = ";
            printHex(number_of_this_disk, 2);
            std::cout << std::endl;
            std::cout << "number_of_the_disk_with_the_start_of_the_central_directory = ";
            printHex(number_of_the_disk_with_the_start_of_the_central_directory, 2);
            std::cout << std::endl;
            std::cout << "total_number_of_entries_in_the_central_directory_on_this_disk = ";
            printHex(total_number_of_entries_in_the_central_directory_on_this_disk, 2);
            std::cout << std::endl;
            std::cout << "total_number_of_entries_in_the_central_directory = ";
            printHex(total_number_of_entries_in_the_central_directory, 2);
            std::cout << std::endl;
            std::cout << "size_of_the_central_directory = ";
            printHex(size_of_the_central_directory, 4);
            std::cout << std::endl;
            std::cout << "offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number = ";
            printHex(offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number, 4);
            std::cout << std::endl;
            std::cout << "ZIP_file_comment_length = ";
            printHex(ZIP_file_comment_length, 2);
            std::cout << std::endl;

            std::cout << "ZIP_file_comment = ";
            printHex(ZIP_file_comment, getDec(ZIP_file_comment_length, 2));
            std::cout << std::endl;
        }
        void init(std::ifstream &inf)
        {
            read(inf, end_of_central_dir_signature, 4);
            read(inf, number_of_this_disk, 2);
            read(inf, number_of_the_disk_with_the_start_of_the_central_directory, 2);
            read(inf, total_number_of_entries_in_the_central_directory_on_this_disk, 2);
            read(inf, total_number_of_entries_in_the_central_directory, 2);
            read(inf, size_of_the_central_directory, 4);
            read(inf, offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number, 4);
            read(inf, ZIP_file_comment_length, 2);

            ZIP_file_comment = new char[getDec(ZIP_file_comment_length, 2)];
            read(inf, ZIP_file_comment, getDec(ZIP_file_comment_length, 2));

            inited = 1;
        }
    };

    std::vector<lefd> vecLEFD;
    archive_decryption_header adh;
    archive_extra_data_record aedr;
    std::vector<central_directory_header> vecCDH;
    zip64_end_of_central_directory_record zip64eocdr;
    zip64_end_of_central_directory_locator zip64eocdl;
    end_of_central_directory_record eocdr;

public:
    zip() = delete;

    ~zip()
    {
        for (unsigned long long i = 0; i < vecLEFD.size(); ++i)
        {
            delete[] vecLEFD[i].file_data;
            vecLEFD[i].file_data = nullptr;
        }
    }

    zip(const char *path = "")
        : path(path)
    {
        // open
        inf.open(path, std::ios::binary);

        if (!inf)
        {
            std::cout << "Error: file not found" << std::endl;
            return;
        }

        // init
        while (true)
        {
            char checker[4];
            read(inf, checker, 4);
            inf.seekg(-4, std::ios_base::cur);

            if (checker[0] == 0x50 && checker[1] == 0x4b && checker[2] == 0x03 && checker[3] == 0x04)
            {
                // [local file header n] // [encryption header n] // [file data n] // [data descriptor n]
                lefd LEFD;

                // [local file header n]
                LEFD.local_file_h.init(inf);
                // LEFD.local_file_h.print();

                // [encryption header n]

                // [file data n]
                if (skip_files)
                {
                    // std::cout << "file_data = ";
                    inf.seekg(LEFD.local_file_h.universal_compressed_size - 16, std::ios_base::cur);
                }
                else
                {
                    LEFD.file_data = new char[LEFD.local_file_h.universal_compressed_size];
                    read(inf, LEFD.file_data, LEFD.local_file_h.universal_compressed_size);
                    // std::cout << "file_data = ";
                    // printHexText(LEFD.file_data, LEFD.local_file_h.universal_compressed_size);
                }
                // std::cout << std::endl;

                // [data descriptor n]
                if (LEFD.local_file_h.general_purpose_bit_flag[0] & 0b00001000)
                {
                    LEFD.data_descript.init(inf, LEFD.local_file_h.zip64);
                    // LEFD.data_descript.print();
                }

                // save
                vecLEFD.push_back(LEFD);
            }
            else if (checker[0] == 0x50 && checker[1] == 0x4b && checker[2] == 0x00 && checker[3] == 0x00)
            {
                // [archive decryption header]
            }
            else if (checker[0] == 0x50 && checker[1] == 0x4b && checker[2] == 0x06 && checker[3] == 0x08)
            {
                // [archive extra data record]
                aedr.init(inf);
                // aedr.print();
            }
            else if (checker[0] == 0x50 && checker[1] == 0x4b && checker[2] == 0x01 && checker[3] == 0x02)
            {
                // [central directory header n]
                central_directory_header cdh;
                cdh.init(inf);
                // cdh.print();

                // save
                vecCDH.push_back(cdh);
            }
            else if (checker[0] == 0x50 && checker[1] == 0x4b && checker[2] == 0x06 && checker[3] == 0x07)
            {
                // Zip64 end of central directory locator
                zip64eocdl.init(inf);
                // zip64eocdl.print();
            }
            else if (checker[0] == 0x50 && checker[1] == 0x4b && checker[2] == 0x06 && checker[3] == 0x06)
            {
                // Zip64 end of central directory record
                zip64eocdr.init(inf);
                // zip64eocdr.print();
            }
            else if (checker[0] == 0x50 && checker[1] == 0x4b && checker[2] == 0x05 && checker[3] == 0x06)
            {
                // [end of central directory record]
                eocdr.init(inf);
                // eocdr.print();

                // std::cout << std::endl
                //           << std::endl
                //           << std::endl;
                break;
            }
            // std::cout << std::endl
            //           << std::endl
            //           << std::endl;
        }

        inf.close();
    }

    void print()
    {
        for (int i = 0; i < vecLEFD.size(); ++i)
        {
            vecLEFD[i].local_file_h.print();
            if (skip_files)
            {
                std::cout << "file_data = ";
            }
            else
            {
                std::cout << "file_data = ";
                printHexText(vecLEFD[i].file_data, vecLEFD[i].local_file_h.universal_compressed_size);
            }
            std::cout << std::endl;
            if (vecLEFD[i].local_file_h.general_purpose_bit_flag[0] & 0b00001000)
            {
                vecLEFD[i].data_descript.print();
            }

            std::cout << std::endl
                      << std::endl
                      << std::endl;
        }

        if (aedr.inited)
        {
            aedr.print();
            std::cout << std::endl
                      << std::endl
                      << std::endl;
        }

        for (int i = 0; i < vecCDH.size(); ++i)
        {
            vecCDH[i].print();

            std::cout << std::endl
                      << std::endl
                      << std::endl;
        }

        if (zip64eocdl.inited)
        {
            zip64eocdl.print();
            std::cout << std::endl
                      << std::endl
                      << std::endl;
        }

        if (eocdr.inited)
        {
            eocdr.print();

            std::cout << std::endl
                      << std::endl
                      << std::endl;
        }
    }
};

int main(int argc, char *argv[])
{
    zip x("example.zip");
    x.print();
    return 0;
}
