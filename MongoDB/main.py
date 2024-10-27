class StringReverser:
    def reverse_words(self, s):
        words = s.split()
        reversed_words = words[::-1]
        return ' '.join(reversed_words)
input_string = input("Enter a string: ")
reverser = StringReverser()
result = reverser.reverse_words(input_string)
print("Reversed string is:", result)