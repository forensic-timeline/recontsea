import csv, re, sys, os


class Normalization:

    def __init__(self, dataset):
        self.dataset = dataset
        self.CSV_INPUT = f"dataset/{dataset}.csv"
        self.CSV_OUTPUT = f"results/{dataset}/result-1-normalization.csv"

    def count_lines(self, path):
        # fast line count
        cnt = 0
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for _ in f:
                cnt += 1
        return cnt

    def normalize_url_encoding(self, url):
        """
        Normalize URL encoding on URLs.
        
        1. Convert ~xx to %xx (example: ~20 to %20)
        2. Replace + with %20 (treat + as space)
        3. Replace literal spaces with %20
        
        Parameters:
        - url: URL string to be normalized
        
        Returns:
        - Normalized URL string
        """
        
        # 1. Convert ~xx to %xx (example: ~20, ~3D, ~2F)
        url = re.sub(r'~([0-9A-Fa-f]{2})', r'%\1', url)
        
        # 2. Replace + with %20
        url = url.replace('+', '%20')
        
        # 3. Replace literal spaces with %20
        url = url.replace(' ', '%20')
        
        return url

    def normalize_message(self, message):
        """
        Message normalization.
            - If http_request: normalize only the URL portion.
            - If not http_request: return the message as is.

            Parameters:
            - message: Complete message string.

            Returns:
            - Normalized message string.
        """
        
        # If not http_request, return as is
        if not message.startswith('http_request:'):
            return message
        
        # Pattern to capture: http_request: METHOD URL HTTP/x.x
        # Group 1: beginning (http_request: METHOD )
        # Group 2: URL path
        # Group 3: ending (HTTP/x.x ...)
        pattern = r'^(http_request:\s*(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+)(\S+)(\s+HTTP/.*)$'
        
        match = re.match(pattern, message)
        
        if match:
            prefix = match.group(1)  # http_request: GET 
            url = match.group(2)      # /wp-content/...
            suffix = match.group(3)   # HTTP/1.1 from: ...
            
            # Normalize only the URL portion
            normalized_url = self.normalize_url_encoding(url)
            
            return prefix + normalized_url + suffix
        
        # If not match pattern, return the original message
        return message

    def run(self):
        os.makedirs(f"results/{self.dataset}", exist_ok=True)

        total_lines = self.count_lines(self.CSV_INPUT)
        print(f"Total lines in {self.CSV_INPUT}: {total_lines}")

        processed = 0

        with open(self.CSV_INPUT, newline='', encoding="utf-8", errors='replace') as f, open(self.CSV_OUTPUT, "w", newline='', encoding="utf-8") as out:
            reader = csv.DictReader(f)
            writer = csv.writer(out)
            
            # Add a new column at the beginning
            fieldnames = ["event_id"] + reader.fieldnames + ["normalized"]
            writer = csv.DictWriter(out, fieldnames=fieldnames)
            writer.writeheader()
            
            for row in reader:
                processed += 1

                # Retrieve and normalize message column
                original_message = row["message"]
                normalized_message = self.normalize_message(original_message)

                # Replace message
                row["normalized"] = normalized_message
                row["event_id"] = processed

                writer.writerow(row)
                    
                # Print progress every 50,000 lines
                if processed % 50000 == 0:
                    print(f"Processed {processed}/{total_lines} lines ({processed/total_lines:.2%})")

        print(f"Conversion finished: {processed}/{total_lines} lines processed.")
