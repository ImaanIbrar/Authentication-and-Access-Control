
def is_likely_email(text):
    """Check if text looks like a valid email address."""
    return '@' in text and '.' in text.split('@')[1]

def is_likely_password(text):
    """Check if text looks like a typical password."""
    has_letters = any(c.isalpha() for c in text)
    reasonable_length = 6 <= len(text) <= 20
    return has_letters and reasonable_length

def score_text(text, text_type='email'):
    """Score text based on likelihood of being readable."""
    score = 0
    
    if text_type == 'email':
        if is_likely_email(text):
            score += 50
        if any(domain in text.lower() for domain in ['gmail', 'yahoo', 'hotmail']):
            score += 30
        if text.lower().endswith('.com'):
            score += 20
    else:  # password scoring
        if is_likely_password(text):
            score += 30
        if any(word in text.lower() for word in ['pass', 'word', 'admin', 'user']):
            score += 20
    
    return score

def caesar_decrypt(text, shift):
    """Caesar cipher decryption"""
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            shifted = chr((ord(char) - start - shift) % 26 + start)
            result += shifted
        else:
            result += char
    return result

def atbash_decrypt(text):
    """Atbash cipher decryption (reverse alphabet)"""
    result = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr(ord('Z') - (ord(char) - ord('A')))
            else:
                result += chr(ord('z') - (ord(char) - ord('a')))
        else:
            result += char
    return result

def rot13_decrypt(text):
    """ROT13 decryption"""
    return caesar_decrypt(text, 13)

def vigenere_decrypt(text, key):
    """Vigenere cipher decryption"""
    result = ""
    key = key.upper()
    key_length = len(key)
    key_as_int = [ord(k) - ord('A') for k in key]
    key_index = 0
    
    for char in text:
        if char.isalpha():
            key_shift = key_as_int[key_index]
            if char.isupper():
                result += chr((ord(char) - ord('A') - key_shift) % 26 + ord('A'))
            else:
                result += chr((ord(char) - ord('a') - key_shift) % 26 + ord('a'))
            key_index = (key_index + 1) % key_length
        else:
            result += char
    return result

def rail_fence_decrypt(text, rails=3):
    """Rail fence cipher decryption"""
    if not text:
        return text
        
    # Create the rail fence pattern
    fence = [[''] * len(text) for _ in range(rails)]
    rail = 0
    direction = 1
    
    # Mark valid positions in fence
    for i in range(len(text)):
        fence[rail][i] = '*'
        rail += direction
        if rail == rails - 1:
            direction = -1
        elif rail == 0:
            direction = 1
            
    # Fill the fence with the text
    index = 0
    for i in range(rails):
        for j in range(len(text)):
            if fence[i][j] == '*':
                fence[i][j] = text[index]
                index += 1
                
    # Read off the decrypted text
    result = ''
    rail = 0
    direction = 1
    for i in range(len(text)):
        result += fence[rail][i]
        rail += direction
        if rail == rails - 1:
            direction = -1
        elif rail == 0:
            direction = 1
    
    return result
def decrypt_all(ciphertext, text_type='email'):
    """Try all supported ciphers and return possible decryptions."""
    results = []
    
    # Try Caesar with all shifts
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        score = score_text(decrypted, text_type)
        results.append({
            'cipher': f'Caesar (shift {shift})',
            'plaintext': decrypted,
            'score': score
        })
    
    # Try Atbash
    decrypted = atbash_decrypt(ciphertext)
    score = score_text(decrypted, text_type)
    results.append({
        'cipher': 'Atbash',
        'plaintext': decrypted,
        'score': score
    })
    
    # Try ROT13
    decrypted = rot13_decrypt(ciphertext)
    score = score_text(decrypted, text_type)
    results.append({
        'cipher': 'ROT13',
        'plaintext': decrypted,
        'score': score
    })
    

    common_keys = ['KEY', 'SECRET', 'CIPHER', 'PASSWORD', 'ADMIN']
    for key in common_keys:
        decrypted = vigenere_decrypt(ciphertext, key)
        score = score_text(decrypted, text_type)
        results.append({
            'cipher': f'Vigenere (key: {key})',
            'plaintext': decrypted,
            'score': score
        })
    

    for rails in range(2, 5):
        decrypted = rail_fence_decrypt(ciphertext, rails)
        score = score_text(decrypted, text_type)
        results.append({
            'cipher': f'Rail Fence ({rails} rails)',
            'plaintext': decrypted,
            'score': score
        })
    
    results.sort(key=lambda x: x['score'], reverse=True)
    return results

encrypted_email = "lpddqleudu86@jpdlo.frp"
encrypted_password = "sdvvzrug"
    
def test_all_decryptions(email,password):

    encrypted_email = email
    encrypted_password = password
    
    print("Testing Email:", encrypted_email)
    print("=" * 50)

    print("\nTop decryption candidates for EMAIL:")
    email_results = decrypt_all(encrypted_email, 'email')
    for i, result in enumerate(email_results[:10], 1):
        print(f"{i}. {result['cipher']}")
        print(f"   Decrypted: {result['plaintext']}")
        print(f"   Score: {result['score']}\n")
    
    print("\nTesting Password:", encrypted_password)
    print("=" * 50)

    print("\nTop decryption candidates for PASSWORD:")
    password_results = decrypt_all(encrypted_password, 'password')
    for i, result in enumerate(password_results[:10], 1):
        print(f"{i}. {result['cipher']}")
        print(f"   Decrypted: {result['plaintext']}")
        print(f"   Score: {result['score']}\n")
    print("Attack Completed!")
    
