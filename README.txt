Ensure you have Python installed on your system. This code uses several Python packages, which can be installed via pip. 
Run the following command to install the necessary packages:
pip install cryptography Pillow numpy

Now run the code.
When the code is run we get a prompt to enter a choice for Encode/Decode/Quit.
Make sure the image to encrypt is in the same location as the python file for convinience otherwise we have to give the entire path.
Change path to the folder with the python script to make sure the code doesn't give error if the image is in the same folder so the path of the image is not mentioned.

Encode:
When encode is selected, we are prompted to enter an image name to perform the steganography on, AES key, name for the new image to be created and the data to be encoded.
Then the message in encrypted and hidden in the picture and saved with the new image name given.

Decode:
When decode is selected, we get a prompt to enter the name of the AES key and the image to decode from.
Then the secret message that is encoded will be revealed and the the PSNR and MSE will also be displayed.

Quit:
This will terminate the program.