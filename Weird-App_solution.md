WEIRD-APP SOLUTION
We were given an app-debug.apk Android application. When running or decompiling, the app only displayed a “Transformed flag” instead of the real one:
Transformed flag: idvi+1{s6e3{)arg2zv[moqa905+
The task was to reverse the transformation to recover the original flag.
________________________________________
Step 1: Inspecting the APK
I unzipped/decompiled the APK using apktool/jadx.
Inside com/example/test2/MainActivity.kt, I found this interesting line:
const-string v4, "Transformed flag: idvi+1{s6e3{)arg2zv[moqa905+"
and a helper function:
.method public static final transformFlag(Ljava/lang/String;)Ljava/lang/String;
________________________________________
Step 2: Understanding the transformFlag Function
Decompiled pseudo-code of transformFlag showed the following logic:
•	Define three character sets:
o	alpha = "abcdefghijklmnopqrstuvwxyz"
o	nums = "0123456789"
o	spec = "!@#$%^&*()_+{}[]|"
•	For each character in the input flag:
1.	If it’s a letter: output = alpha[(pos + index) % 26]
2.	If it’s a digit: output = nums[(pos + 2*index) % 10]
3.	If it’s a special char: output = spec[(pos + index^2) % len(spec)]
In other words, each character was shifted depending on its position index.
________________________________________
Step 3: Reversing the Transformation
To undo the mapping:
•	Letters: pos = (t - i) % 26
•	Digits: pos = (t - 2*i) % 10
•	Specials: pos = (t - i^2) % len(spec)
I wrote a quick Python script:
alpha = "abcdefghijklmnopqrstuvwxyz"
nums  = "0123456789"
spec  = "!@#$%^&*()_+{}[]|"

def invert_transform(transformed):
    out = []
    for i, ch in enumerate(transformed):
        if ch in alpha:
            t = alpha.index(ch)
            k = (t - i) % len(alpha)
            out.append(alpha[k])
        elif ch in nums:
            t = nums.index(ch)
            k = (t - 2*i) % len(nums)
            out.append(nums[k])
        elif ch in spec:
            t = spec.index(ch)
            k = (t - i*i) % len(spec)
            out.append(spec[k])
        else:
            out.append(ch)
    return "".join(out)

print(invert_transform("idvi+1{s6e3{)arg2zv[moqa905+"))
________________________________________
Step 4: Recovering the Flag
Running the script produced:
ictf{1_l0v3_@ndr0id_stud103}
________________________________________
Final Flag
ictf{1_l0v3_@ndr0id_stud103}
