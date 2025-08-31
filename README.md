This is an basic SQL Injection scanner Tool written in python.

Installation :
 
	git clone https://github.com/The-xploit/basic_sqli.git

 Install all requirements available in the requirements.txt file.

	pip3 install -r requirements.txt

Usage: 

  	python3 basic_sqli.py [options]

Options:
 
	-h, --help         show this help message and exit

	--url=URL          Target URL (Provide full parameter of the url (eg: http://testphp.vulnweb.com/listproducts.php?cat=1))
 
	--headers=HEADERS  Custom headers for requests

	--verbose          Enable verbose output

	--threads=THREADS  Number of concurrent threads

	--delay=DELAY      Delay in seconds for time-based SQLi

	--output=OUTPUT    File to save the results

Example:

	python3 basic_sqli.py --url https://testphp.vulnweb.com/listproducts.php?cat=1
