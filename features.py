import math #importing math library for mathematical functions
def calculate_entropy(file_path,chunk_size=2048): #here, i am defining a function called calculate_entropy with the parameter that defines the file that the function is analyzing
    try:
        with open(file_path, "rb") as f: #here, i am using the with open...as f architecture which opens a file and closes it automatically
            #file_path defines the file, and "rb" means read binary instead of txt
            data = f.read(chunk_size) #reading the file in chunks of 2048 bytes
            if not data:
                return 0.0 #checks if file is empty, and returns 0 if so
            byte_counts = [0] * 256 # creates a list of 256 zeros for each possible byte value so we can count each later on
            for b in data: 
                byte_counts[b] +=1  #here is where we count the occurrences of each byte value by 1
                entropy=0.0 #define entropy function as 0 initially
            for count in byte_counts:
                if count==0: 
                    continue #skip when occurrence number is 0
                p = count / len(data) #simple prob. calc
                entropy -= p * math.log2(p) #this is entropy formula
            return round(entropy, 3) #returns entropy rounded to 3 dec vals
    except Exception:
        return -1 #failed to read, perms denied, etc
    
''' 
what are the applications in ML and python for entropy?
In machine learning and Python, entropy is commonly used in various applications, including:
1. Decision Trees: Entropy is used as a criterion for splitting nodes in decision tree algorithms like ID3 and C4.5. It helps determine the best feature to split the data by measuring the impurity or uncertainty in the dataset.
2. Feature Selection: Entropy can be used to evaluate the importance of features in a dataset
    by calculating the information gain associated with each feature. Features that provide higher information gain are considered more relevant for the model.
3. Clustering: In clustering algorithms, entropy can be used to measure the quality of clusters. Lower entropy indicates more homogeneous clusters, while higher entropy suggests more diverse clusters.
4. Anomaly Detection: Entropy can be used to identify anomalies in data by measuring the uncertainty or randomness in the data distribution. Anomalies often exhibit higher entropy compared to normal data points.
5. Natural Language Processing (NLP): Entropy is used in NLP tasks such as language modeling and text classification to measure the uncertainty in word distributions and to evaluate the performance of language models.
6. Image Processing: In image processing, entropy can be used to analyze the texture and complexity of images. It can help in tasks like image segmentation and classification.
'''
def score_file(file_row):
    score=0.0 #start of scoring function
    if file_row["entropy"] > 7.5: #so if the entropy function above returns a value greater than 7.5 (high entropy) add 2 to the score

        score += 2
    if file_row["entropy"] < 0.5: #very low entropy could indicate a file is padded or empty
        score+=1
    
    suspicious_exts = ['.exe', '.dll', '.scr', '.vbs', '.bat', '.ps1'] #list of suspicious file extensions
    if file_row["extension"] in suspicious_exts:
        score +=2

    rare_exts = ['.xyz', '.abc', '.tmp'] #list of rare file extensions
    if file_row["extension"] in rare_exts:
        score +=1 

    if file_row["extension"] in suspicious_exts and file_row["entropy"] < 2.0: #if the file has a suspicious extension but low entropy, add 1 to the score
        score+=2 #if .exe and low entropy, even more suspicious

    if file_row["name"].startswith('.'): #if the file name starts with a dot, it is hidden/system file
        score +=1


    if file_row["size"] > 50_000_000: #if the file size is greater than 50MB, add 1 to the score
        score +=1

    
    return score


'''
current entropy calculator and scoring function, will be optimized and developed
in near future
'''
#future ideas: check for known bad hashes, check for digital signatures, check for known packers/obfuscators
#integrate with VirusTotal or other threat intelligence sources
#check for recent creation/modification dates
#check for known bad file paths or directories
#check for known bad IPs/domains in file metadata
#check for known bad registry keys/values in file metadata
#check for known bad URLs in file metadata
#check for known bad email addresses in file metadata

