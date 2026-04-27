def main():
    key = input("Zadajte kľúč: ")
    correct = 0

    # 1
    if len(key) < 9:
        return correct
    correct += 1

    # 2
    if key[0] == "x":
        correct += 1

    # 3
    if key[1].isdigit() and int(key[1]) == 8:
        correct += 1

    # 4
    if key[2].isupper() and key[2].lower() == "p":
        correct += 1

    # 5
    if key[3] == chr(0x73):
        correct += 1

    # 6
    if key[4] == "\x32":
        correct += 1

    # 7
    if key[5].isdigit() and int(key[5]) % 7 == 3:
        correct += 1

    # 8
    if key[6].isdigit() and pow(int(key[6]), 2, 5) == 1:
        correct += 1

    # 9
    if (ord(key[7]) - ord('0')).to_bytes(4, "little") == b"\x04\x00\x00\x00":
        correct += 1

    # 10
    if key[8] == key[0]:
        correct += 1

    return correct

if __name__ == "__main__":
    grade = main()
    print("Počet správnych: " + str(grade) + "/10")