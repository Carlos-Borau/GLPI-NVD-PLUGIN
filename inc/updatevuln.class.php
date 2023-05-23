<?php

class PluginNvdUpdatevuln extends CommonGLPI {

    /**
     * Check if can view item
     *
     * @since 1.0.0
     *
     * @return boolean
     */
    static function canView() {
        
        return Config::canView();
    }

    /**
     * Get tab name for displayed item
     *
     * @since 1.0.0
     *
     * @return boolean
     */
    function getTabNameForItem(CommonGLPI $item, $withtemplate=0) {

        return self::createTabEntry(__('Update Vuln'));
    }

    /**
     * Display tab content for given Software
     *
     * @since 1.0.0
     *
     * @param CommonGLPI $item       Software for which to display the CPE association
     * @param int $tabnum
     * @param int $withtemplate
     *
     * @return boolean
     */
    static function displayTabContentForItem(CommonGLPI $item, $tabnum=1, $withtemplate=0) {

        if ($item::getType() === Central::getType()) {
            
            #self::cronUpdateVulnTask();

            $apiKey = self::getNvdApiKey();

            // Configure connection to NVD API
            $NVD_Connection = new PluginNvdNvdconnection();
            $NVD_Connection->setUrlParams([
                CVE_ID => 'CVE-2023-30063'
            ]);
            $NVD_Connection->setRequestHeaders([
                API_KEY => $apiKey
            ]);

            // Get CVE records from NVD
            $records = $NVD_Connection->launchRequest();

            // Vulnerabilities retrieved for this page
            $vulnerabilities = $records['vulnerabilities'];

            foreach ($vulnerabilities as $vulnerability) {

                $record = $vulnerability['cve'];

                // Configuration(s)
                $configurations = [];

                if (isset($record['configurations'])) {

                    foreach($record['configurations'] as $vendor_configs) {

                        $cpeMatches = $vendor_configs['nodes'][0]['cpeMatch'];

                        $CPE = new PluginNvdCpe($cpeMatches[0]['criteria']);

                        print($CPE->get_CPE_WFN());

                        foreach($cpeMatches as $cpeMatch) {
    
                            $criteria = $cpeMatch['criteria'];
    
                            echo "\t$criteria<br>";
                        }
    
                        echo "<br>";
                    }
                }
            }
        }
        
        return true;
    }

    /**
     * Give cron information on the specified task
     * 
     * @since 1.0.0
     * 
     * @param CommonDBTM $task for log
     * 
     * @return array    Array of information
     */
    static function cronInfo($name) {

        switch ($name) {
            case 'updatevulntask' :
               return array('description' => __('Updates the list of known vulnerabilities present on devices managed by GLPI'));
         }
         return [];
    }

    /**
     * Task to update list of vulnerabilities present on the devices managed by GLPI
     * 
     * @since 1.0.0
     * 
     * @param string    $name  Name of the task
     * 
     * @return bool     true if completed false if not    
     */
    static function cronUpdateVulnTask($task=NULL) {

        // Get NVD API key from database
        $apiKey = self::getNvdApiKey();

        // Get next vulnerability ID from database
        $nextVulnID = self::getNextVulnId();

        // If no API Key is set the task can't proceed
        if ($apiKey == NULL) { return false; }

        // Request all software versions installed on any device
        $allVersions = self::requestAllSoftwareInstallations();

        // Request known vulnerable software versions 
        $vulnVersions = self::requestAllVulnerableSoftwareVersions('softwareversions_id');

        // Remove vulnerable versions that are no longer installed on any device
        self::removeOldVulnerableVersions($allVersions, $vulnVersions);

        // Get every present vulnerability CVE ID
        $CVEs = self::getKnownCVEs();

        // Get every CPE vendor and product name associations
        [$vendors, $products] = self::getAllSoftwareCPEAssociations();

        // For each installed verion look for vulnerabilities
        foreach ($allVersions as $version_id) {

            // Get software ID and version number
            [$software_id, $version] = self::getSoftwareIDAndVersion($version_id);

            // Check if software has necessary CPE vendor and product associations
            if (array_key_exists($software_id, $products)) {

                $product = $products[$software_id];
                $vendor = $vendors[$software_id];

                // Compose CPE name
                $CPE = new PluginNvdCpe();
                $CPE->set_CPE_attributes([
                    CPE_PART => 'a',
                    CPE_VENDOR => $vendor,
                    CPE_PRODUCT => $product,
                    CPE_VERSION => (strlen($version) != 0) ? $version : '-'
                ]);
                $CPE_Name = $CPE->get_CPE_WFN();

                // Get known CVEs associated with a particular version
                $version_CVEs = self::getSoftwareVersionCVEs($version_id);

                // Get CVE records for given software version
                $CVE_Records = self::retrieveCVERecords($CPE_Name, $apiKey);

                // CVE IDs retrieved from NVD
                $NVD_CVEs = array_keys($CVE_Records);

                // Missing references to known vulnerabilities
                $missingVulnerabilities = array_diff($NVD_CVEs, array_keys($CVEs));

                // Create records in GLPI database for new vulnerabilities and update known CVEs
                self::insertNewVulnerabilities($missingVulnerabilities, $CVE_Records, $nextVulnID, $CVEs);

                // Missing references to known vulnerabilities for software version
                $missingVersionVulnerabilities = array_diff($NVD_CVEs, $version_CVEs);

                // Create associations in GLPI database between software version and known vulnerabilities
                self::insertNewVersionVulnerabilities($missingVersionVulnerabilities, $version_id, $CVEs);
            }

            // CVE IDs associated with some software versions
            $installedVulnerabilities = self::requestAllVulnerableSoftwareVersions('vuln_id');

            // Remove vulnerabilities no longer present on any device managed by GLPI
            self::removeVulnerabilities(array_values($CVEs), $installedVulnerabilities);
        }

        return true;
    }

    /**
     * Retrieve CVE records from NVD database
     * 
     * @since 1.0.0
     * 
     * @param string    $CPE_Name CPE name for software version
     * @param string    $apiKey Key for NVD API
     * 
     * @return array    Array values
     */
    private static function retrieveCVERecords($CPE_Name, $apiKey) {

        // Configure connection to NVD API
        $NVD_Connection = new PluginNvdNvdconnection();
        $NVD_Connection->setUrlParams([
            CPE_NAME => $CPE_Name,
            VULNERABLE => NULL
        ]);
        $NVD_Connection->setRequestHeaders([
            API_KEY => $apiKey
        ]);

        $processedRecords = 0;
        $CVE_Records = [];

        // When too many records are present they must be retrieved through multiple requests
        do {
            // Set page index
            $NVD_Connection->setUrlParams([START_INDEX => $processedRecords]);

            // Get CVE records from NVD
            $records = $NVD_Connection->launchRequest();

            // Number of total results
            $totalResults = $records['totalResults'];

            // Number of CVE records retrieved for this page
            $resultsPerPage = $records['resultsPerPage'];

            // Vulnerabilities retrieved for this page
            $vulnerabilities = $records['vulnerabilities'];

            foreach ($vulnerabilities as $vulnerability) {

                $record = $vulnerability['cve'];

                // CVE ID
                $CVE_ID = $record['id'];

                // Description(s)
                $descriptions = [];
        
                foreach($record['descriptions'] as $description) {
                    $descriptions[$description['lang']] = $description['value'];
                }

                // Configuration(s)
                $configurations = [];

                foreach($record['configurations'] as $vendor_configs) {

                    $cpeMatches = $vendor_configs['nodes']['cpeMatch'];

                    foreach($cpeMatches as $cpeMatch) {

                        $criteria = $cpeMatch['criteria'];

                        echo "$criteria<br>";
                    }

                    echo "<br>";
                }

                // CVSS Metrics
                $main_metrics = array_values($record['metrics'])[0][0];

                // Vulnerability scores
                $base_score     = $main_metrics['cvssData']['baseScore'];
                $exploit_score  = $main_metrics['exploitabilityScore'];
                $impact_score   = $main_metrics['impactScore'];

                $CVE_Records[$CVE_ID] = array(
                    'descriptions' => $descriptions,
                    'configurations' => $configurations,
                    'base_score' => $base_score,
                    'exploitability_score' => $exploit_score,
                    'impact_score' => $impact_score
                );
            }

            $processedRecords += $resultsPerPage;

        } while ($processedRecords < $totalResults);

        return $CVE_Records;
    }

    /**
     * Combine values from database query result into an array
     * 
     * @since 1.0.0
     * 
     * @return array    Array values
     */
    private static function pushResToArray($res, $value, $key=NULL) {

        $array = [];

        if ($key == NULL) {

            foreach ($res as $id => $row) {
                $array[] = $row[$value];
            }

        } else {

            foreach ($res as $id => $row) {
                $array[$row[$key]] = $row[$value];
            }
        }

        return $array;
    }

    /**
     * Queries the GLPI database and returns the API key set for the NVD API
     * 
     * @since 1.0.0
     * 
     * @return string    NVD API key
     */
    private static function getNvdApiKey() {

        global $DB;

        /***********************************************************************************************
         * Request api key from glpi configuration
         * 
         *  SELECT api_key
         *  FROM glpi_plugin_nvd_config 
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'api_key',
                             'FROM' => 'glpi_plugin_nvd_config']);

        if ($res->numrows() != 0) {

            $row = $res->current();

            return $row['api_key'];
        }

        return NULL;
    }

    /**
     * Queries the GLPI database and returns the current autoincrement value for the table 
     * glpi_plugin_nvd_vulnerabilities
     * 
     * @since 1.0.0
     * 
     * @return int    autoincrement value
     */
    private static function getNextVulnId() {

        global $DB;

        /***********************************************************************************************
         * Request MAX id from glpi_plugin_nvd_vulnerabilities
         * 
         *  SELECT AUTO_INCREMENT
         *  FROM INFORMATION_SCHEMA.TABLES
         *  WHERE TABLE_SCHEMA = glpi AND TABLE_NAME = glpi_plugin_nvd_vulnerabilities
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'AUTO_INCREMENT',
                             'FROM' => 'INFORMATION_SCHEMA.TABLES',
                             'WHERE' => ['TABLE_SCHEMA' => 'glpi',
                                         'TABLE_NAME' => 'glpi_plugin_nvd_vulnerabilities']]);

        $row = $res->current();

        return $row['AUTO_INCREMENT'];
    }

    /**
     * Queries the GLPI database and returns the IDs of all installed software versions
     * 
     * @since 1.0.0
     * 
     * @return array    Array of installed software versions
     */
    private static function requestAllSoftwareInstallations() {

        global $DB;

        /***********************************************************************************************
         * Request all software installations on the devices managed by GLPI
         * 
         *  SELECT DISTINCT softwareversions_id
         *  FROM glpi_items_softwareversions 
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'softwareversions_id',
                             'DISTINCT' => true,
                             'FROM' => 'glpi_items_softwareversions']);

        return self::pushResToArray($res, 'softwareversions_id');
    }

    /**
     * Queries the GLPI database and returns:
     * -The IDs of all known vulnerable software versions if $column == 'softwareversions_id'
     * -The IDs of all known vulnerabilities associated with some software versions if $column == 'vuln_id'
     * 
     * @since 1.0.0
     * 
     * @return array    Array of IDs
     */
    private static function requestAllVulnerableSoftwareVersions($column) {

        global $DB;

         /***********************************************************************************************
         * Request all known vulnerable software versions
         * 
         *  SELECT DISTINCT $column
         *  FROM glpi_plugin_nvd_vulnerable_versions 
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => $column,
                             'DISTINCT' => true,
                             'FROM' => 'glpi_plugin_nvd_vulnerable_versions']);

        return self::pushResToArray($res, $column);
    }

    private static function removeOldVulnerableVersions($allVersions, $vulnVersions) {

        global $DB;

        $versionsToRemove = array_diff($vulnVersions, $allVersions);

        if($versionsToRemove) {

            /***********************************************************************************************
             * Remove all vulnerable versions no longer installed on any device
             * 
             *  DELETE FROM glpi_plugin_nvd_vulnerable_versions
             *  WHERE softwareversions_id IN $versionsToRemove
             **********************************************************************************************/
            $DB->delete(
                'glpi_plugin_nvd_vulnerable_versions', [
                    'softwareversions_id' => $versionsToRemove
                ]
            );
        }
    }

    /**
     * Queries the GLPI database and returns a CVE ID for every vulnerability associated with a given software version
     * 
     * @since 1.0.0
     * 
     * @return array    Array of vulnerability IDs
     */
    private static function getSoftwareVersionCVEs($version_id) {

        global $DB;

        /***********************************************************************************************
         * Request all vulnerabilities associated with a given software version
         * 
         *  SELECT cve_id 
         *  FROM glpi_plugin_nvd_vulnerabilities
         *  INNER JOIN glpi_plugin_nvd_vulnerable_versions
         *   ON glpi_plugin_nvd_vulnerabilities.id = glpi_plugin_nvd_vulnerable_versions.vuln_id
         *  WHERE softwareversions_id = $version_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'cve_id',
                             'FROM' => 'glpi_plugin_nvd_vulnerabilities',
                             'INNER JOIN' => ['glpi_plugin_nvd_vulnerable_versions' => ['FKEY' => ['glpi_plugin_nvd_vulnerabilities' => 'id',
                                                                                                   'glpi_plugin_nvd_vulnerable_versions' => 'vuln_id']]] ,
                             'WHERE' => ['softwareversions_id' => $version_id]]);

        return self::pushResToArray($res, 'cve_id');
    }

    /**
     * Queries the GLPI database and returns the software ID and version number for a given software version
     * 
     * @since 1.0.0
     * 
     * @return array    Array containing the software ID and the version number
     */
    private static function getSoftwareIDAndVersion($version_id) {

        global $DB;

        /***********************************************************************************************
         * Request software ID and version number of a software version
         * 
         *  SELECT softwares_id, name AS version
         *  FROM glpi_softwareversions
         *  WHERE id = $version_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['softwares_id', 'name AS version'],
                             'FROM' => 'glpi_softwareversions',
                             'WHERE' => ['id' => $version_id]]);

        $row = $res->current();

        return [$row['softwares_id'], str_replace(' ', '_', $row['version'])];
    }

    /**
     * Queries the GLPI database and returns all CVE IDs present
     * 
     * @since 1.0.0
     * 
     * @return array    Array containing the CVE IDs
     */
    private static function getKnownCVEs() {

        global $DB;

        /***********************************************************************************************
         * Request numeric IDs for every created vulnerability entry on the GLPI database
         * 
         *  SELECT id, cve_id
         *  FROM glpi_plugin_nvd_vulnerabilities
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['id', 'cve_id'],
                             'FROM' => 'glpi_plugin_nvd_vulnerabilities']);

        return self::pushResToArray($res, 'id', 'cve_id');
    }

    /**
     * Queries the GLPI database and returns all CPE vendor and product names associations
     * 
     * @since 1.0.0
     * 
     * @return array    Array containing the CPE vendor and product names associations
     */
    private static function getAllSoftwareCPEAssociations() {

        global $DB;

        /***********************************************************************************************
         * Request software ID and version number of a software version
         * 
         *  SELECT softwares_id, vendor_name, product_name
         *  FROM glpi_plugin_nvd_cpe_software_associations
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['softwares_id', 'vendor_name', 'product_name'],
                             'FROM' => 'glpi_plugin_nvd_cpe_software_associations']);

        $vendor_associations = self::pushResToArray($res, 'vendor_name', 'softwares_id');
        $product_associations = self::pushResToArray($res, 'product_name', 'softwares_id');

        return [$vendor_associations, $product_associations];
    }

    /**
     * Inserts new vulnerability records into the GLPI database
     * 
     * @since 1.0.0
     * 
     * @param array     $missingVulnerabilities     List of CVE IDs of vulnerabilities to insert
     * @param array     $CVE_Records                List of CVE records
     * @param int       $nextVulnID                 Numeric id for the next inserted vulnerability
     * 
     * @return void
     */
    private static function insertNewVulnerabilities($missingVulnerabilities, $CVE_Records, &$nextVulnID, &$knownCVEs) {

        global $DB;

        foreach ($missingVulnerabilities as $CVE_ID) {

            $CVE_Record = $CVE_Records[$CVE_ID];

            // Vulnerability descriptions
            $descriptions = $CVE_Record['descriptions'];

            // Vulnerability configurations
            $configurations = $CVE_Record['configurations'];

            // Vulnerability base score
            $base_score = $CVE_Record['base_score'];

            // Vulnerability exploitability score
            $exploitability_score = $CVE_Record['exploitability_score'];

            // Vulnerability impact score
            $impact_score = $CVE_Record['impact_score'];

            /***********************************************************************************************
             * Insert new vulnerability into GLPI database
             * 
             *  INSERT INTO glpi_plugin_nvd_vulnerabilities
             *  (cve_id, base_score, exploitability_score, impact_score)
             *  VALUES ($CVE_ID, $base_score, $exploitability_score, $impact_score)
             **********************************************************************************************/
            $DB->insert(
                'glpi_plugin_nvd_vulnerabilities', [
                    'cve_id' => $CVE_ID,
                    'base_score' => $base_score,
                    'exploitability_score' => $exploitability_score,
                    'impact_score' => $impact_score
                ]
            );

            // Insert conrresponding descriptions
            self::insertVulnerabilityDescriptions($nextVulnID, $descriptions);

            // Insert corresponding configurations
            self::insertVulnerabilityConfigurations($nextVulnID, $configurations);

            // Update known CVEs
            $knownCVEs[$CVE_ID] = $nextVulnID;

            $nextVulnID++;
        }
    }

    /**
     * Inserts descriptions for a newly created vulnerability
     * 
     * @since 1.0.0
     * 
     * @param int       $vuln_id                Numeric id for the newly inserted vulnerability
     * @param array     $descriptions           List of descriptions in different languages
     * 
     * @return void
     */
    private static function insertVulnerabilityDescriptions($vuln_id, $descriptions) {

        global $DB;

        foreach ($descriptions as $language => $description) {

            /***********************************************************************************************
             * Insert new vulnerability description into glpi database
             * 
             *  INSERT INTO glpi_plugin_nvd_vulnerability_descriptions
             *  (vuln_id, language, description) VALUES ($vuln_id, $language, $description)
             **********************************************************************************************/
            $DB->insert(
                'glpi_plugin_nvd_vulnerability_descriptions', [
                    'vuln_id' => $vuln_id,
                    'language' => $language,
                    'description' => $description
                ]
            );
        }
    }

    /**
     * Inserts configurations for a newly created vulnerability
     * 
     * @since 1.0.0
     * 
     * @param int       $vuln_id                Numeric id for the newly inserted vulnerability
     * @param array     $configurations         List of configurations for different softwares
     * 
     * @return void
     */
    private static function insertVulnerabilityConfigurations($vuln_id, $configurations) {

        global $DB;

        foreach ($configurations as $vendor => $products) {

            foreach ($products as $product => $configuration) {

                /***********************************************************************************************
                 * Insert new vulnerability configuration into glpi database
                 * 
                 *  INSERT INTO glpi_plugin_nvd_vulnerability_configurations
                 *  (vuln_id, vendor_name, product_name, configuration) 
                 *  VALUES ($vuln_id, $vendor, $product, $configuration)
                 **********************************************************************************************/
                $DB->insert(
                    'glpi_plugin_nvd_vulnerability_configurations', [
                        'vuln_id' => $vuln_id,
                        'vendor_name' => $vendor,
                        'product_name' => $product,
                        'configuration' => $configuration
                    ]
                );
            }
        }
    }

    /**
     * Inserts new associations between a software version and known vulnerabilities into the GLPI database
     * 
     * @since 1.0.0
     * 
     * @param array     $missingVersionVulnerabilities      List of CVE IDs to associate to a given version
     * @param int       $version_id                         ID of the software version
     * @param array     $knownCVEs                          List of known CVE IDs with corresponding numeric IDs
     * 
     * @return void
     */
    private static function insertNewVersionVulnerabilities($missingVersionVulnerabilities, $version_id, $knownCVEs) {

        global $DB;

        foreach ($missingVersionVulnerabilities as $CVE_ID) {

            $vulnID = $knownCVEs[$CVE_ID];

            /***********************************************************************************************
             * Insert new vulnerable software version into GLPI database
             * 
             *  INSERT INTO glpi_plugin_nvd_vulnerable_versions
             *  (vuln_id, softwareversions_id) VALUES ($vulnID, $version_id)
             **********************************************************************************************/
            $DB->insert(
                'glpi_plugin_nvd_vulnerable_versions', [
                    'vuln_id' => $vulnID,
                    'softwareversions_id' => $version_id
                ]
            );
        }
    }

    /**
     * Removes vulnerabilities no longer present on any device managed by GLPI
     * 
     * @since 1.0.0
     * 
     * @param array     $$allVulnerabilities        List of all known vulnerability IDs 
     * @param array     $installedVulnerabilities   List of known vulnerability IDs to be associated with any installed software version
     * 
     * @return void
     */
    private static function removeVulnerabilities($allVulnerabilities, $installedVulnerabilities){

        global $DB;

        // CVEs no longer installed
        $vulnerabilitiesToRemove = array_diff($allVulnerabilities, $installedVulnerabilities);

        if ($vulnerabilitiesToRemove) {

            /***********************************************************************************************
             * Remove all vulnerable versions no longer installed on any device
             * 
             *  DELETE FROM glpi_plugin_nvd_vulnerabilities
             *  WHERE id IN $vulnerabilitiesToRemove
             **********************************************************************************************/
            $DB->delete(
                'glpi_plugin_nvd_vulnerabilities', [
                    'id' => $vulnerabilitiesToRemove
                ]
            );
        }
    }
}

?>