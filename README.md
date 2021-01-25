# Frame_Analyzer
A wireshark like frame analyzer (network course project)

Project structure:

The project being carried out in Java, it will be structured in classes:

- Analyzer.java: Contains the protocol analysis methods and the methods necessary for reading the file.

- Test.java: Contains the "main" of our project, where the execution begins, or the files are created and the display initialized.

- TestJtree.java: Contains the structure of the tree structure and the display window

- MyDragDropListener: Contains the drag and drop system for the frame file to be analyzed.

The Analyzer.java file contains the important part of the project, each protocol analysis is performed by a corresponding function, Ethernet, IP, TCP, HTTP. There are also the methods for managing the read pointer on the file.
