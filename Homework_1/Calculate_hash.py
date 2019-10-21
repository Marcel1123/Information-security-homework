import hashlib


def read_data_from_the_file(file_name):
    with open(file_name, 'r') as reader:
        return reader.read()


def write_data_to_a_file(file_name, text):
    file = open(file_name, 'w')
    file.write(text)
    file.close()


def convert_to_byte_array(text):
    st = str(text)
    bites = ' '.join(format(ord(x), 'b') for x in st)
    return bites


def hash_print(hash_name, hash_parameter):
    return "%s este: %s" % (hash_name, hash_parameter)


def print_text_hash_pair(hash_1, hash_2, common_bits):
    return "Hashurile %s si %s au %s biti comuni." % (hash_1, hash_2, common_bits)


def count_equals_characters(hash_parameter_1, hash_parameter_2):
    cnt = 0
    for letter in range(len(hash_parameter_1), 2):
        if hash_parameter_1[letter] == hash_parameter_2[letter]\
                and hash_parameter_1[letter + 1] == hash_parameter_2[letter + 1]:
            cnt = cnt + 1
    return cnt


if __name__ == "__main__":
    file1_content = read_data_from_the_file('f_1.txt')
    file2_content = read_data_from_the_file('f_2.txt')

    hash1_md5 = hashlib.md5(file1_content.encode())
    write_data_to_a_file('h1_md5.txt', hash1_md5.hexdigest())
    print(hash_print("h1_md5", hash1_md5.hexdigest()))

    hash1_sha256 = hashlib.sha256(file1_content.encode())
    write_data_to_a_file('h1_sha256.txt', hash1_sha256.hexdigest())
    print(hash_print("h1_sh256", hash1_sha256.hexdigest()))

    hash2_md5 = hashlib.md5(file2_content.encode())
    write_data_to_a_file('h2_md5.txt', hash2_md5.hexdigest())
    print(hash_print("h2_md5", hash2_md5.hexdigest()))

    hash2_sha256 = hashlib.sha256(file2_content.encode())
    write_data_to_a_file('h2_sha256.txt', hash2_sha256.hexdigest())
    print(hash_print("h2_sha256", hash2_sha256.hexdigest()))

    data_from_h1_md5 = read_data_from_the_file("h1_md5.txt")
    data_from_h2_md5 = read_data_from_the_file("h2_md5.txt")
    print(print_text_hash_pair("h1_md5", "h2_md5", count_equals_characters(data_from_h1_md5,data_from_h2_md5)))

    data_from_h1_sha256 = read_data_from_the_file("h1_sha256.txt")
    data_from_h2_sha256 = read_data_from_the_file("h2_sha256.txt")
    print(print_text_hash_pair("h1_sha256", "h2_sha256", count_equals_characters(data_from_h1_sha256, data_from_h2_sha256)))