# Conda

Conda allows you to create environments, where dependencies, files, and packages are kept separately. To create a new environment use `conda create --name environame packages-to-use`. To activate an environment, use `source activate environame` and to list available environments use `conda info --envs`

use the command `anaconda-navigator` to open the navigator (I can't get it to stick on the side for some reason) - or use `jupyter notebook --allow-root` to get into a jupyter notebook. (if you weren't root this isn't necessary.)



inner functions, lambdas, variable scoping rules for inner functions and lambdas

For structured data `collections.namedtuples` are more readable than dictionaries, lists and tuples, and less verbose than classes

Constructs to help write simpler code include `all()`, `any()`, list comprehension, `map()`, `functools.reduce()`, `zip()`, and `enumerate()`

Useful functions from the `itertools` module include `groupby()`, `accumulate()`, `product()`, and `combinations()`

A common style guide used in EPI is PEP 8. The authors also suggest using 'Python for Informatics' at <a href="http://www.pythonlearn.com/book_007.pdf">http://www.pythonlearn.com/book_007.pdf</a>.

The authors also suggest effective python and head first design patterns.

In Python, everything is an object.

'Language Questions' Chapter in EPI Python

**Garbage collection** refers to finding data objects which cannot be accessed in the future and reclaiming the resources of these unusable objects such as memory. Garbage-collected languages include Java, C#, Python, and most scripting languages. C is non-garbage-collected. Garbage collected languages use **reference counting** or **tracing** to find relevant objects, and discard the rest as garbage. Python uses reference counting, which can immediately reclaim objects when their reference count is 0. The tradeoff is that you need to store an additional integer-value per object. Tracing can be performed in a separate thread, but it pauses all threads which leads to **nondeterministic** performance.

**Reference cycles** occur when objects $A$ and $B$ reference each other, for example $A.u=B$ and $B.v=A$, which leads the reference count to never drop below 1. Garbage collectors should look for these, and remove them. Garbage collectors also make use of heuristics for speed - for example, objects are assigned generations, and younger generations are examined first for removal.

In Python, assignment does not copy, it only assigns a variable to a target. For mutable objects, a copy is needed to change values without changing the original.

A **compound** object is an object made of objects.

A **shallow** copy (`copy.copy()`) constructs a new compound object of references to the objects found in the original. A **deep** copy (`copy.deepcopy()`) constructs a new compound object and then inserts copies of objects found in the original. This difference is only relevant for compound objects. Copying is defensive and may be avoided if the object will not be mutated. If an object is immutable, there is no need to copy it.

An **iterator** is any object that has:

- `__iter__()`, which returns the iterator object, and is used in `for` and `in` statements. The
- `__next__()`, which returns the next value in the iteration, until there are no more

A **generator** uses the function call stack to implicitly store the state of the iterator. Every generator is an iterator, but iterators can have additional functionality.

A **decorator** ?????

A **list** `[1,2,3]` is similar to a **tuple** `(1,2,3)` because both represent sequences and both use the `in` operator for membership checking. They are different because tuples are immutable. Immutable objects are more container-friendly (mutable objects might have a changed hashcode if they have been changed) and thread-safe. Tuples can be put in sets and used as map keys, while lists cannot.

`*args` is used to pass a variable length argument list. The parameter doesn't need to be called args, it just must be preceded by `*`. This argument must appear after all regular arguments.

`**kwargs` is used when passing a variable number of keyword arguments to a function. Keyword arguments are quite different from named arguments??

When an attempt is made to execute a statement or expression and it results in an error, it is called an exception.

- a `try` block is used when a user might have to try several different inputs
- an `except` block is used for exceptions or special cases. There are a number of built-in exception types in Python which should be learned and used whenever possible
- a `finally` block is always executed, regardless of whether an exception was raised. This can be used to avoid duplicating code in try and except
- an `else` block is executed in the absence of exceptions
- `raise` is used to create or propagate exceptions upward


The rules for variable scope are as follows. A variable can appear in an expression and it can also be assigned to. When the variable appears in an expression, Python searches 1. the current function 2. enclosing scopes 3. the module containing code (global scope) 4. built-in scope (`open`)

In Python 3, use `nonlocal` to have an assignment to a variable use an enclosing function's scope.

When calling a function, some arguments must be specified by name. Functions which do not need to be specified by name are called **keyword** (positional) arguments. Keyword arguments make the function call cleaner and they also make it easier to refactor functions into having more arguments. When a function is defined, arguments can be given default values. Default arguments are only evaluated once, when a module is loaded, and they are shared across all callers.

As a rule, mutable objects should have `None` as their default value
## Primitive Types

The built-in types in python include numeric (float, int), sequences (list), mappings (dict), classes, instances, and exceptions

- bitwise operators include `&amp;,|,&gt;&gt;,&lt;&lt;,~,^`
- key methods for numeric types include `abs()`,`math.ceil()`,`math.floor()`,`min(x,y)`,`max(x,y)`,`pow(x,y)` or `x ** y` and `math.sqrt()`
- to compare floats, use `math.isclose()`
- key mehtods in `random` include `random.randrange(x)`, `random.randint(x,y)`, `random.random()`, `random.shuffle(A)`, and `random.choice(A)`

## Arrays

In Python, arrays are provided by the `list` type. Lists are dynamically resized. The `tuple` type is similar, but immutable.

- a list is instantiated `[1,2,3,4]` or `list(range(100))`
- a 2D array is instantiated `[[1,2,],[3,4,]]`
- basic operations on lists include `len(A)`, `A.append()`, `A.remove()`, `A.insert(i,y)`
- to check if a value is present in an array, use `a in A`
- key methods for `list` include `min(A)`, `max(A)`
- Slicing an array allows you to select all the indecies including and after index i and before j with `A[i:j]`, select including and after the ith index using `A[i:]`, select up to before the ith index using `A[:i]` select the last i using `A[-i:]`, select from -i to -j using `A[-i:-j]`, reverse a list using `A[::-1]`, rotate a list using `A[k:]` + `A[:k]`, skip by k using `A[i:j:k]`, and create a shallow copy using `B = A[:]`
- list comprehension in Python consists of 1. an input sequence, 2. an iterator over the input sequence, 3. a logical condition over the operator, 4. an expression that yields elements of derived list. For example,`[x**2 for x in range(6) if x % 2 ==0]` yields `[0,4,16]`

## Strings

Strings are also stored as lists in python, so many of the key operators and functions are the same as those for arrays. Other key operators include +, , `s in t`, `s.strip()`, `s.startswith(prefix)`, `s.endswith(suffix)`, `'string'.split(',')` `','.join('strings', 'in' , 'here')`, `s.tolower()`. Strings are immutable
## Lists

lists in python there is not much detail in EPI book
## Stacks, Queues, Deques

Key methods in the `list` type for using stacks include

- `s.append(e)` pushes an element onto the stack
- `s[-1]` retrieves but does not remove the element at the top of the stack
- `s.pop()` will remove and return the element at the top of the stack
- `len(s) == 0` tests if the stack is empty


Key methods in `collections.deque` include

- `q.append(e)` pushes an element onto the queue
- `q[0]` retrieves but does not remove the element at the front, `q[-1]` does the same to the back
- `q.popleft()` removes and returns the element at the front of the queue

## Heaps

In Python, heaps are implemented in the `heapq` module. The key functions for this module are:

- `heapq.heapify()` transforms elements in L into a heap-in-place
- `heapq.nlargest(k,L)` and `heapq.nsmallest(k,L)` return the k largest or smallest elements in L.
- `heapq.heappush(h,e)` pushes a new element on the heap
- `heapq.heappop(h)` pops the smallest element from the heap
- `heapq.heappushpop(h,a)` pushes a on the heap and then pops and returns the smallest element
- `e=h[0]` returns the smallest element without popping it
- `heapq` provides a min-heap, so to use a max-heap, use negative values

## Searching

In python, use the `bisect` module for binary search functions on a sorted list `a`.

- the index of the first element greater than or equal to a given value is given by `bisect_left(a,x)`
- the index of the first element greater than a given value is given by `bisect_right(a,x)`
- If all elements are less than x, these functions return `len(a)`

## Hash Tables

Commonly used hash table based data structures in Python include `set`, which simply stores keys, and `dict`, `collections.defaultdict` and `collections.Counter` which all store key-value pairs. All do not allow for duplicate keys, unlike list.

- In `set`, important operations include `s.add()`, `s.remove()`, `s.discard()`, `x in s`, `x &lt;= y` (is x a subset of y) and, `x - y` elements in x that are not in y


Iteration over key-value pairs yields the keys. To iterate over key-value pairs, use `items()`, to iterate over values use `values()`, to return to iterating over keys use `keys()`

The builtin `hash` function can make implementing hash functions much easier
## Sorting

Sort in-place in python using `sort()`, which only updates the calling list, and returns `None`. If the `key` is `none`, it is assumed to be a function which maps list elements to comparable objects.

Sort iterables using `sorted()`. This takes an iterable and returns a new list containing all items from the iterable in ascending order
## Binary Search Trees

In Python, use `sortedcontainers` for sorted sets and dictionaries. In EPI, the authors use `bintrees` for pedagogy? In `bintrees`:

- `insert()` inserts a new element e into a binary search tree
- `discard()` removes e from the binary search tree if it is present
- `minitem()` yields the smallest key-value pair and `maxitem()` yields the largest
- `minkey()` yields the smallest key and `maxkey()` yields the largest
- `pop_min()` removes and returns the smallest key-value pair and `pop_max()` removes and returns the largest
