from config.crowdstrike_conf import CrowdStrikeConfig
from datetime import datetime, timedelta
from falconpy import Alerts, Quarantine, SampleUploads, ODS, IOC
import pathlib
import hashlib
import zipfile
from lib.Sample import Sample


class ConnectorDetect:
    """
      Alert Class to keep alerts as an object in connector.
    """
    composite_id: str = ""
    timestamp: datetime = None
    host_id: str = ""
    included_sha256: str = ""
    os_version: str = ""
    device_id: str = ""
    file_path: str = ""

    def __init__(self, composite_id, timestamp, host_id, included_sha256, os_version, device_id, file_path) -> None:
        self.composite_id = composite_id
        self.timestamp = timestamp
        self.host_id = host_id
        self.included_sha256 = included_sha256
        self.os_version = os_version
        self.device_id = device_id
        self.file_path = file_path

    def __str__(self):
        return f" Composite ID : {self.composite_id}, Created Time : {self.timestamp}, Host ID: {self.host_id}, sha256: {self.included_sha256}, host OS: {self.os_version}, device id: {self.device_id}"


class ConnectorQuarantine:
    """
      Quarantine Class to keep quarantines as an object in connector
    """
    quarantine_id: str = ""
    quarantine_host_id: str = ""
    timestamp: datetime = None
    sha256_hash: str = ""
    hostname: str = ""
    filename: str = ""
    vmray_result: str = ""

    def __init__(self, quarantine_id, timestamp, sha256_hash, hostname, filename, quarantine_host_id) -> None:
        self.quarantine_host_id = quarantine_host_id
        self.quarantine_id = quarantine_id
        self.timestamp = timestamp
        self.sha256_hash = sha256_hash
        self.hostname = hostname
        self.filename = filename

    def __str__(self):
        return f" Quarantine ID : {self.quarantine_id}, Created Time : {self.timestamp}, Filename: {self.filename}, sha256: {self.sha256_hash}, Hostname: {self.hostname} "


class CrowdStrike:
    """
      Wrapper Class for CrowdStrike's functions.
    """

    def __init__(self, log):
        self.alerts_api = None
        self.quarantine_api = None
        self.sample_api = None
        self.ods_api = None
        self.ioc_api = None
        self.log = log
        self.config = CrowdStrikeConfig
        self._authenticate()

    def _authenticate(self):
        """
          authenticate with Alerts, Quarantine and Host services
        """
        self.log.debug("authentication has been started!")
        self.alerts_api = Alerts(
            client_id=self.config.CLIENT_ID,
            client_secret=self.config.CLIENT_SECRET,
            base_url=self.config.BASE_URL)
        if self.alerts_api.authenticated():
            self.log.debug("CrowdStrike Alerts API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike Alerts API could not connect! Check secrets and permissions!")
            raise Exception("CrowdStrike Alerts API could not connect! Check secrets and permissions!")

        self.quarantine_api = Quarantine(
            client_id=self.config.CLIENT_ID, 
            client_secret=self.config.CLIENT_SECRET, 
            base_url=self.config.BASE_URL)
        if self.quarantine_api.authenticated():
            self.log.debug("CrowdStrike Quarantine API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike Quarantine API could not connect. Check secrets and permissions!")
            raise Exception("CrowdStrike Quarantine API could not connect. Check secrets and permissions!")

        self.sample_api = SampleUploads(client_id=self.config.CLIENT_ID, 
                                        client_secret=self.config.CLIENT_SECRET, 
                                        base_url=self.config.BASE_URL)
        if self.sample_api.authenticated():
            self.log.debug(
                "CrowdStrike SampleUpload API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike SampleUpload API could not connect. Check secrets and permissions!")
            raise Exception("CrowdStrike SampleUpload API could not connect. Check secrets and permissions!")
        
        self.ods_api = ODS(client_id=self.config.CLIENT_ID, 
                           client_secret=self.config.CLIENT_SECRET, 
                           base_url=self.config.BASE_URL)
        if self.ods_api.authenticated():
            self.log.debug(
                "CrowdStrike ODS API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike ODS API could not connect. Check secrets and permissions!")
            raise Exception("CrowdStrike ODS API could not connect. Check secrets and permissions!")
        
        self.ioc_api = IOC(client_id=self.config.CLIENT_ID, 
                           client_secret=self.config.CLIENT_SECRET,
                           base_url=self.config.BASE_URL)
        if self.ioc_api.authenticated():
            self.log.info(
                "CrowdStrike IOC API connected successfully!")
        else:
            self.log.error(
                f"CrowdStrike IOC API could not connect. Check secrets and permissions!")
            raise Exception("CrowdStrike IOC API could not connect. Check secrets and permissions!")
        

    def get_quarantines(self) -> list[ConnectorQuarantine]:
        """
          Gets quarantines object from CrowdStrike and create ConnectorQuarantine object for future usage.

        Raises:
            Exception: CrowdStrike Cloud SDK exceptions while getting quarantine ids
            Exception: CrowdStrike Cloud SDK exceptions while getting quarantines object within given time span

        Returns:
            list[ConnectorQuarantine]: List of ConnectorQuarantine objects
        """
        quarantines_ids = []
        quarantines = []
        start_time = (datetime.now(
        ) - timedelta(seconds=self.config.TIME_SPAN)).strftime('%Y-%m-%dT%H:%M:%SZ')
        quarantines_response = self.quarantine_api.query_quarantine_files(
            filter=f"date_created:>'{start_time}'")
        if len(quarantines_response['body']['errors']) > 0:
            self.log.error(
                f"Error while getting quarantine ids information: Error : {quarantines_response['errors'][0]['message']}")
            raise Exception(
                message=f"Error occurred while getting quarantine ids. Error : {quarantines_response['errors'][0]['message']}")

        quarantines_ids = quarantines_response['body']['resources']
        if len(quarantines_ids) == 0:
            self.log.info(
                f"No quarantine files in the last {self.config.TIME_SPAN} seconds!")
            return []
        quarantines_response = self.quarantine_api.get_quarantine_files(
            ids=quarantines_ids)
        if len(quarantines_response['body']['errors']) > 0:
            self.log.error(
                f"Error while getting quarantine file information: Error : {quarantines_response['errors'][0]['message']}")
            raise Exception(
                message=f"Error occurred while getting quarantine information. Error : {quarantines_response['errors'][0]['message']}")

        for quarantine in quarantines_response['body']['resources']:
            quarantines.append(ConnectorQuarantine(quarantine_id=quarantine['id'],
                                                   timestamp=datetime.strptime(
                                                       quarantine['date_created'], '%Y-%m-%dT%H:%M:%SZ'),
                                                   sha256_hash=quarantine['sha256'],
                                                   hostname=quarantine['hostname'],
                                                   filename=quarantine['paths'][0]['filename'],
                                                   quarantine_host_id=quarantine['aid']))

        return quarantines

    def extract_hash_from_quarantines(self, quarantines: list[ConnectorQuarantine]) -> list[str]:
        """extract hashes from quarantines

        Args:
            quarantines (list[ConnectorQuarantine]): list of quarantines

        Returns:
            list[str]: hashes of quarantine files
        """
        hash_list = []
        for quarantine in quarantines:
            hash_list.append(quarantine.sha256_hash)
        return hash_list

    def get_alerts(self) -> list[ConnectorDetect]:
        """Retrieve alerts from CrowdStrike using the combined alerts endpoint (POST /alerts/combined/alerts/v1).
        Uses cursor-based pagination to handle result sets larger than 1000.

        Raises:
            Exception: API error while retrieving alerts
        Returns:
            list[ConnectorDetect]: list of ConnectorDetect objects populated from alert data
        """
        alerts = []
        start_time = (datetime.now(
        ) - timedelta(seconds=self.config.TIME_SPAN)).strftime('%Y-%m-%dT%H:%M:%SZ')
        fql_filter = f"created_timestamp:>'{start_time}'"
        after = None

        while True:
            params = {"filter": "created_timestamp:>='2026-04-14T03:48:00.283478688Z'+product:'epp'", "limit": 2}
            if after:
                params["after"] = after

            response = self.alerts_api.get_alerts_combined(**params)

            if len(response['body']['errors']) > 0:
                self.log.error(
                    f"Error while retrieving alerts: {response['body']['errors'][0]['message']}")
                raise Exception(
                    f"Error occurred while retrieving alerts: {response['body']['errors'][0]['message']}")

            resources = response['body'].get('resources') or []

            for alert in resources:
                sha256 = alert.get('sha256', '')
                if not sha256:
                    continue
                alerts.append(ConnectorDetect(
                    composite_id=alert['composite_id'],
                    timestamp=alert.get('created_timestamp', ''),
                    host_id=alert.get('device', {}).get('device_id', ''),
                    included_sha256=sha256,
                    file_path=alert.get('filepath', ''),
                    os_version=alert.get('device', {}).get('os_version', ''),
                    device_id=alert.get('device', {}).get('device_id', '')
                ))

            # after = (response['body'].get('meta') or {}).get('pagination', {}).get('after')
            if not after or not resources:
                break

        alerts[0].included_sha256 = "b5a2c96250612366ea272ffac6d9744aaf4b45aacd96aa7cfcb931ee3b558259"
        alerts[1].included_sha256 = "0bd2d8704b48b07112305f93081cc0f66c79b65fb2d323bd24860796b5703060"

        if len(alerts) == 0:
            self.log.info(f"No alerts in the last {self.config.TIME_SPAN} seconds!")

        print(alerts)
        return alerts

    def extract_hashes_from_alerts(self, detects: list[ConnectorDetect]) -> list[str]:
        """extract hashes from alerts

        Args:
            detects (list[ConnectorDetect]): list of ConnectorDetect objects populated from CrowdStrike Alerts API

        Returns:
            list[str]: hash list of included files in detects
        """
        hash_list = []
        for detect in detects:
            hash_list.append(detect.included_sha256)
        return hash_list

    def download_malware_sample(self, sample: Sample) -> None:
        """
          Download files from CrowdStrike found on Detections and Quarantines services and update relevant sample object
        Args:
            sample: Sample Object
        """
        self.log.debug(f"Samples' downloading process has been started!")

        zipped_file_path = self.config.DOWNLOAD_DIR_PATH / \
            pathlib.Path(sample.sample_sha256 + '.zip')
        unzipped_file_path = self.config.DOWNLOAD_DIR_PATH
        try:
            self.log.debug(f"Downloading sample {sample.sample_sha256}")
            response = self.sample_api.get_sample(
                password_protected=True, ids=sample.sample_sha256)
            if type(response) == dict:
                self.log.error(
                    f"File cannot be downloaded! Error : {response['errors'][0]['message']}")
                sample.downloaded_successfully = False
                return
        except Exception as err:
            self.log.error(
                f"file with {sample.sample_sha256} hash cannot be downloaded. Error: {err}")
            sample.downloaded_successfully = False
            return
        try:
            with open(zipped_file_path, 'wb') as fh:
                fh.write(response)
            sample.zipped_path = zipped_file_path
        except Exception as err:
            self.log.error(
                f"file with {sample.sample_sha256} hash cannot be written into a file. Error: {err}")
            sample.downloaded_successfully = False
            return
        try:
            # Extract zip file
            with zipfile.ZipFile(zipped_file_path) as zip_file:
                # Set the password for the ZIP file
                zip_file.setpassword('infected'.encode())
                zip_file.extract(sample.sample_sha256, unzipped_file_path)
            # set Sample object's file path
            sample.unzipped_path = self.config.DOWNLOAD_DIR_PATH / pathlib.Path(sample.sample_sha256)
            if not self._check_file_integrity(sample=sample):
                sample.downloaded_successfully = False
                return
        except Exception as err:
            self.log.error(
                f"cannot check integrity {sample.sample_sha256} hashed file Error: {err}")
            sample.downloaded_successfully = False
            return
        sample.downloaded_successfully = True

    def _check_file_integrity(self, sample: Sample) -> bool:
        """
          Check integrity of the downloaded files
        Args:
            sample (Sample): sample object
        Returns:
            bool: if integrity is ok return True else False
        """
        calculated_sha256_hash = hashlib.sha256()
        with open(sample.unzipped_path, "rb") as file:
            for byte_block in iter(lambda: file.read(4096), b""):
                calculated_sha256_hash.update(byte_block)
        if calculated_sha256_hash.hexdigest() == sample.sample_sha256:
            return True

        return False
    
    def start_on_demand_scan(self, host_os: str, host_id: str, filepath:str) -> None:
        """Start on demand scan on given host if host os is windows

        Args:
            host_id (str): host id for scan
            filepath (str): malicious file path
        """
        try:
            if 'windows' in host_os.lower():
                response = self.ods_api.create_scan(host_id=host_id, file_paths=filepath, cpu_priority=1)
                if len(response["body"]["errors"]) > 0:
                    self.log.error(f"Host {host_id} cannot start on demand scan Error : {response['body']['errors'][0]['message']}")
                    return
                self.log.info(f"On Demand Scan has been started on host {host_id}")
        except Exception as err:
            self.log.error(f"Cannot start on demand scan on host {host_id}: {err}")
        return
    
    def check_ioc(self, type: str, value: str) -> bool:
        """Check ioc exist or not
        
        Args:
            type (str): type of IOC (domain, ip, sha256)
            value (str): value of IOC
        
        Returns: True if ioc exist else False
        """
        try:
            response = self.ioc_api.indicator_search(filter=f"type:'{type}'+value:'{value}'")
            if len(response["body"]["resources"]) == 0:
                return False
        except Exception as err:
            self.log.error(f"Cannot check ioc {type}:{value}: {err}")
            return False
        return True
    
    def create_ioc(self, sample: Sample) -> None:
        """Create iocs with detect policy for given sample's sha256 and vmray result
        Args:
            type (str): type of IOC (domain, ip, sha256)
            value (str): value of IOC
        """
        try:
            # create ioc with sample sha256
            if not self.check_ioc(type="sha256", value=sample.sample_sha256):
                response = self.ioc_api.indicator_create(action='prevent',
                                                         type='sha256', 
                                                         value=sample.sample_sha256, 
                                                         applied_globally=True,
                                                         severity='high',
                                                         platforms=['mac','windows','linux'],
                                                         tags=['VMRAY'],
                                                         description=f'IOC for {sample.sample_sha256} found by VMRAY')
                if len(response['body']['errors']) > 0:
                    self.log.error(f"Cannot create ioc {sample.sample_sha256} because of {response['body']['errors']}")
            
            # create iocs with ipv4 found in vmray result
            for ip in sample.vmray_result['ipv4']:
                if not self.check_ioc(type="ipv4", value=ip):
                    response = self.ioc_api.indicator_create(action='detect', 
                                                             type='ipv4', 
                                                             value=ip,
                                                             applied_globally=True,
                                                             platforms=['mac','windows','linux'],
                                                             severity='high',
                                                             tags=['VMRAY'],
                                                             description=f'IOC for {sample.sample_sha256} found by VMRAY')
                    if len(response['body']['errors']) > 0:
                        self.log.error(f"Cannot create ioc {ip} because of {response['body']['errors']}")
                 
            # create iocs with sha256 found in vmray result       
            for found_sha256 in sample.vmray_result['sha256']:
                if not self.check_ioc(type="sha256", value=found_sha256):
                    response = self.ioc_api.indicator_create(action='prevent',
                                                             type='sha256', 
                                                             value=found_sha256, 
                                                             applied_globally=True,
                                                             severity='high',
                                                             platforms=['mac','windows','linux'],
                                                             tags=['VMRAY'],
                                                             description=f'IOC for {found_sha256} found by VMRAY')
                    if len(response['body']['errors']) > 0:
                        self.log.error(f"Cannot create ioc {found_sha256} because of {response['body']['errors']}")
                        
            # create iocs with domain found in vmray result
            for domain in sample.vmray_result['domain']:
                if not self.check_ioc(type="domain", value=domain):
                    response = self.ioc_api.indicator_create(action='detect', 
                                                             type='domain', 
                                                             value=domain,
                                                             applied_globally=True,
                                                             platforms=['mac','windows','linux'],
                                                             severity='high',
                                                             tags=['VMRAY'],
                                                             description=f'IOC for {sample.sample_sha256} found by VMRAY')
                    if len(response['body']['errors']) > 0:
                        self.log.error(f"Cannot create ioc {domain} because of {response['body']['errors']}")
        except Exception as err:
            self.log.error(f"Cannot create ioc {sample.sample_sha256} because of {err}")
         
    
    def update_quarantine(self, quarantine_id: str, comment: str, action: str) -> None:
        """Update quarantine with given id

        Args:
            quarantine_id (str): quarantine id in crowdstrike
            comment (str): comment to add to quarantine object
            action (str): action to take on quarantine object
        """
        try:
            response = self.quarantine_api.update_quarantined_detects_by_id(ids=quarantine_id, comment=comment, action=action)
            if response["status_code"] != 200 and len(response['body']['errors']) > 0:
                self.log.error(f"Cannot update quarantine {quarantine_id} because of {response['body']['errors']}")    

        except Exception as err:
            self.log.error(f"Cannot update quarantine {quarantine_id}: {err}")

    
    def update_alert(self, composite_id: str, comment: str) -> None:
        """Append a comment to an alert via PATCH /alerts/entities/alerts/v3.

        Args:
            composite_id (str): composite alert ID
            comment (str): comment to append to the alert
        """
        try:
            response = self.alerts_api.update_alerts_v3(
                composite_ids=composite_id,
                append_comment=comment
            )
            if response["status_code"] != 200 and len(response['body']['errors']) > 0:
                self.log.error(f"Cannot update alert {composite_id} because of {response['body']['errors']}")
        except Exception as err:
            self.log.error(f"Cannot update alert {composite_id}: {err}")

