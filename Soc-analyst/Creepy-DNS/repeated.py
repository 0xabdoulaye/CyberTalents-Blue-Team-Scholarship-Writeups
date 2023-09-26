with open('output2_single_line.txt', 'r') as file:
    content = file.read()

unique_content = ''.join(char for i, char in enumerate(content) if char != content[i - 1])

with open('output2_single_line_cleaned.txt', 'w') as file:
    file.write(unique_content)
