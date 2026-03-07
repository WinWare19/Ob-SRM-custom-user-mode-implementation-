# Ob-SRM-custom-user-mode-implementation-
a user mode implementation of two major kernel executive managers : 
# Object Manager
a kernel executive manager responsible for the creation and deletion of objects and lifecycles tracking through reference counting, it has a private namespace used to store object names ( some objects are unnamed ), each object belongs to a specific type which defines the valid access rights and many other common pieces of information. Objects has headers where metadata are stored such as current reference and handle counts, security descriptor .. etc.
Objects are considered protected resources so user mode clients cannot access them directly, although they must use an indirect reference called a HANDLE, each handle points to exactly a single object, the handle is simply a value that's used as an index in the current process' handle table, each handle entry stores the granted access rights and a pointer to the start of the obejct and many other pieces of informtion.
# Security Reference Monitor 
responsible for access checking to determine if a user has the right to do such an operation on an object or on the system.
