import pefile  # For parsing and analyzing Portable Executable (PE) files
import math  # For mathematical functions, including logarithms
import pickle  # For serializing and deserializing objects
import yara  # For pattern matching and malware detection using YARA rules
import os  # For interacting with the operating system, including file operations


class PEAnalyzer:
    def __init__(self, model_path, yara_rules_dir):
        """
        Initialize the PEAnalyzer with a machine learning model and YARA rules.

        Parameters:
            model_path (str): Path to the machine learning model file.
            yara_rules_dir (str): Directory containing YARA rule files.
        """
        self.model = self.load_model(model_path)
        self.yara_rules = self.load_yara_rules(yara_rules_dir)

    def load_yara_rules(self, yara_rules_dir):
        """
        Load YARA rules from the specified directory.

        Parameters:
            yara_rules_dir (str): Directory containing YARA rule files.

        Returns:
            list: A list of compiled YARA rules.
        """
        rule_files = [f for f in os.listdir(yara_rules_dir) if f.endswith('.yar')]
        rules = []
        for rule_file in rule_files:
            rule_path = os.path.join(yara_rules_dir, rule_file)
            try:
                rules.append(yara.compile(filepath=rule_path))
            except:
                continue

        return rules

    @staticmethod
    def calculate_entropy(data):
        """
        Calculate the Shannon entropy of the given data.

        Parameters:
            data (bytes): The data to calculate the entropy for.

        Returns:
            float: The entropy value.
        """
        if not data:
            return 0.0

        entropy = 0
        byte_counts = [0] * 256

        for byte in data:
            byte_counts[byte] += 1

        for count in byte_counts:
            if count:
                frequency = float(count) / len(data)
                entropy -= frequency * math.log(frequency, 2)

        return entropy

    def get_resource_entropies(self, pe):
        """
        Get the entropies of the resources in the PE file.

        Parameters:
            pe (pefile.PE): The PE file object.

        Returns:
            list: A list of entropy values for the resources.
        """
        entropies = []
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return entropies

        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            if hasattr(resource_lang, 'data'):
                                data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                                   resource_lang.data.struct.Size)
                                entropy = self.calculate_entropy(data)
                                entropies.append(entropy)
        return entropies

    def get_pe_headers(self, pe):
        """
        Extract various header and entropy values from the PE file.

        Parameters:
            pe (pefile.PE): The PE file object.

        Returns:
            list: A list of extracted header and entropy values.
        """
        section_entropies = [section.get_entropy() for section in pe.sections]
        resource_entropies = self.get_resource_entropies(pe)

        headers = {
            "DllCharacteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
            "Characteristics": pe.FILE_HEADER.Characteristics,
            "Machine": pe.FILE_HEADER.Machine,
            "VersionInformationSize": len(pe.VS_VERSIONINFO) if hasattr(pe, 'VS_VERSIONINFO') else 0,
            "SectionsMaxEntropy": max(section_entropies) if section_entropies else 0,
            "Subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "ImageBase": pe.OPTIONAL_HEADER.ImageBase,
            "MajorSubsystemVersion": pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            "SizeOfOptionalHeader": pe.FILE_HEADER.SizeOfOptionalHeader,
            "ResourcesMaxEntropy": max(resource_entropies) if resource_entropies else 0,
            "ResourcesMinEntropy": min(resource_entropies) if resource_entropies else 0,
            "MajorOperatingSystemVersion": pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            "SectionsMinEntropy": min(section_entropies) if section_entropies else 0,
            "SectionsMeanEntropy": sum(section_entropies) / len(section_entropies) if section_entropies else 0,
        }
        return list(headers.values())

    @staticmethod
    def load_model(model_path):
        """
        Load a machine learning model from the specified file.

        Parameters:
            model_path (str): Path to the machine learning model file.

        Returns:
            object: The loaded machine learning model.
        """
        with open(model_path, "rb") as file:
            model = pickle.load(file)
        return model

    def analyze_file(self, file_data):
        """
        Analyze the given file data for potential malware.

        Parameters:
            file_data (bytes): The file data to analyze.

        Returns:
            str: A message indicating whether malware was detected.
        """
        pe = pefile.PE(data=file_data)
        headers = self.get_pe_headers(pe)
        prediction = self.model.predict([headers])

        # YARA rule check
        for rule in self.yara_rules:
            yara_matches = rule.match(data=file_data)
            if yara_matches:
                return "Malware detected by YARA: " + ', '.join([match.rule for match in yara_matches])

        return "Malware" if prediction[0] == 1 else "No virus detected"
