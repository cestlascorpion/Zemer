#include "BaseX.h"

#include <assert.h>

using namespace std;

void TestBase16() {
    {

        string str = "Hello, World!";
        string encoded = BaseEncoding::Base16Encode(str);
        assert(encoded == "48656C6C6F2C20576F726C6421");
        string decoded = BaseEncoding::Base16Decode(encoded);
        assert(decoded == str);
    }
    {
        string str = "";
        string encoded = BaseEncoding::Base16Encode(str);
        assert(encoded == "");
        string decoded = BaseEncoding::Base16Decode(encoded);
        assert(decoded == str);
    }
    {
        string str = "A";
        string encoded = BaseEncoding::Base16Encode(str);
        assert(encoded == "41");
        string decoded = BaseEncoding::Base16Decode(encoded);
        assert(decoded == str);
    }
    printf("TestBase16 passed\n");
}

void TestBase32() {
    {
        string str = "Hello, World!";
        string encoded = BaseEncoding::Base32Encode(str);
        assert(encoded == "JBSWY3DPFQQFO33SNRSCC===");
        string decoded = BaseEncoding::Base32Decode(encoded);
        assert(decoded == str);
    }
    {
        string str = "";
        string encoded = BaseEncoding::Base32Encode(str);
        assert(encoded == "");
        string decoded = BaseEncoding::Base32Decode(encoded);
        assert(decoded == str);
    }
    {
        string str = "A";
        string encoded = BaseEncoding::Base32Encode(str);
        assert(encoded == "IE======");
        string decoded = BaseEncoding::Base32Decode(encoded);
        assert(decoded == str);
    }
    printf("TestBase32 passed\n");
}

void TestBase64() {
    {
        string str = "Hello, World!";
        string encoded = BaseEncoding::Base64Encode(str);
        assert(encoded == "SGVsbG8sIFdvcmxkIQ==");
        string decoded = BaseEncoding::Base64Decode(encoded);
        assert(decoded == str);
    }
    {
        string str = "";
        string encoded = BaseEncoding::Base64Encode(str);
        assert(encoded == "");
        string decoded = BaseEncoding::Base64Decode(encoded);
        assert(decoded == str);
    }
    {
        string str = "A";
        string encoded = BaseEncoding::Base64Encode(str);
        assert(encoded == "QQ==");
        string decoded = BaseEncoding::Base64Decode(encoded);
        assert(decoded == str);
    }
    printf("TestBase64 passed\n");
}

int main() {
    TestBase16();
    TestBase32();
    TestBase64();
    return 0;
}