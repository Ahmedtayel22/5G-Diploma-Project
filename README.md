## Important Notes for Checking

I made the following assumptions for the current version of the program:

1. **Capture size** should be a multiple of 10 (e.g., 10, 20, 30, etc.), which means sending an integer number of frames (not subframes).
2. **ORAN data type** is always fixed and read from the IQ file.
3. The program supports up to **SC = 60**.

These assumptions can be modified later in the code, but for now, this is the current program support.
