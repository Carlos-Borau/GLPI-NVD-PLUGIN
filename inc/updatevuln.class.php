<?php

class PluginNvdUpdatevuln extends CommonGLPI {

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
        $apiKey = PluginNvdDatabaseutils::getNvdApiKey();

        // If no API Key is set the task can't proceed
        if (is_null($apiKey)) { return false; }

        // Get next vulnerability ID from database
        $nextVulnID = PluginNvdDatabaseutils::getNextId('glpi_plugin_nvd_vulnerabilities');

        // Get every present vulnerability CVE ID
        $CVEs = self::getKnownCVEs();

        // Update vulnerabilities related to software applications
        self::updateSoftwareVulnerabilities($apiKey, $nextVulnID, $CVEs);

        // CVE IDs associated with some software versions
        $installedSoftwareVulnerabilities = self::requestAllVulnerableVersions('glpi_plugin_nvd_vulnerable_software_versions', 'vuln_id');

        // Update vulnerabilities related to operating systems
        self::updateSystemVulnerabilities($apiKey, $nextVulnID, $CVEs);

        // CVE IDs associated with some operating system versions
        $installedSystemVulnerabilities = self::requestAllVulnerableVersions('glpi_plugin_nvd_vulnerable_system_versions', 'vuln_id');

        // Vulnerabilities no longer present on any device managed by GLPI
        $oldVulnerabilities = array_diff(array_values($CVEs), $installedSoftwareVulnerabilities, $installedSystemVulnerabilities);

        // Remove vulnerabilities no longer present on any device managed by GLPI
        self::removeVulnerabilities($oldVulnerabilities);

        return true;
    }

    /**
     * Update vulnerabilities related to applications present on any device managed by GLPI
     * 
     * @since 1.0.0
     * 
     * @param string    $apiKey         Key for NVD API
     * @param int       $nextVulnID     Numeric id for the next inserted vulnerability
     * @param array     $CVEs           List of known vulnerabilities and their IDs on the database
     * 
     * @return void
     */
    private static function updateSoftwareVulnerabilities($apiKey, &$nextVulnID, &$CVEs) {

        $vuln_versions_table = 'glpi_plugin_nvd_vulnerable_software_versions';
        $vuln_version_column = 'softwareversions_id';

        // Request all software versions installed on any device
        $allVersions = self::requestAllSoftwareInstallations();

        // Request known vulnerable software versions 
        $vulnVersions = self::requestAllVulnerableVersions($vuln_versions_table, $vuln_version_column);

        // Software versions to remove  from vulnerable versions table
        $versionsToRemove = array_diff($vulnVersions, $allVersions);

        // Remove vulnerable versions that are no longer installed on any device
        self::removeOldVulnerableVersions($versionsToRemove, $vuln_versions_table, $vuln_version_column);

        // Get every CPE vendor and product name associations
        [$vendors, $products] = self::getAllSoftwareCPEAssociations();

        // For each installed version look for vulnerabilities
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
                $version_CVEs = self::getVersionCVEs($version_id, $vuln_versions_table, $vuln_version_column);

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
                self::insertNewVersionVulnerabilities($missingVersionVulnerabilities, $version_id, $CVEs, $vuln_versions_table, $vuln_version_column);
            }
        }
    }

    /**
     * Update vulnerabilities related to operating systems installed on any device managed by GLPI
     * 
     * @since 1.0.0
     * 
     * @param string    $apiKey         Key for NVD API
     * @param int       $nextVulnID     Numeric id for the next inserted vulnerability
     * @param array     $CVEs           List of known vulnerabilities and their IDs on the database
     * 
     * @return void
     */
    private static function updateSystemVulnerabilities($apiKey, &$nextVulnID, &$CVEs) {

        $vuln_versions_table = 'glpi_plugin_nvd_vulnerable_system_versions';
        $vuln_version_column = 'system_configuration';

        // Request all operating system versions installed on any device
        $allVersions = self::requestAllOSInstallations();

        // Request known vulnerable operating system versions 
        $vulnVersions = self::requestAllVulnerableVersions($vuln_versions_table, $vuln_version_column);

        // Operating system versions to remove from vulnerable versions table
        $versionsToRemove = array_diff(array_column($allVersions, 'configuration'), $vulnVersions);

        // Remove vulnerable versions that are no longer installed on any device
        self::removeOldVulnerableVersions($versionsToRemove, $vuln_versions_table, $vuln_version_column);

        // For each installed version look for vulnerabilities
        foreach ($allVersions as $version_data) {

            $vendor         = $version_data[CPE_VENDOR];
            $product        = $version_data[CPE_PRODUCT];
            $version        = $version_data[CPE_VERSION];
            $configuration  = $version_data['configuration'];

            // Compose CPE name
            $CPE = new PluginNvdCpe();
            $CPE->set_CPE_attributes([
                CPE_PART => 'o',
                CPE_VENDOR => $vendor,
                CPE_PRODUCT => $product,
                CPE_VERSION => (strlen($version) != 0) ? $version : '-'
            ]);
            $CPE_Name = $CPE->get_CPE_WFN();

            // Get known CVEs associated with a particular OS version
            $version_CVEs = self::getVersionCVEs($configuration, $vuln_versions_table, $vuln_version_column);

            // Get CVE records for given OS version
            $CVE_Records = self::retrieveCVERecords($CPE_Name, $apiKey);

            // CVE IDs retrieved from NVD
            $NVD_CVEs = array_keys($CVE_Records);

            // Missing references to known vulnerabilities
            $missingVulnerabilities = array_diff($NVD_CVEs, array_keys($CVEs));

            // Create records in GLPI database for new vulnerabilities and update known CVEs
            self::insertNewVulnerabilities($missingVulnerabilities, $CVE_Records, $nextVulnID, $CVEs);

            // Missing references to known vulnerabilities for software version
            $missingVersionVulnerabilities = array_diff($NVD_CVEs, $version_CVEs);

            // Create associations in GLPI database between operating system version and known vulnerabilities
            self::insertNewVersionVulnerabilities($missingVersionVulnerabilities, $configuration, $CVEs, $vuln_versions_table, $vuln_version_column);
        }
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
            VULNERABLE => NULL,
            NOREJECTED => NULL
        ]);
        $NVD_Connection->setRequestHeaders([
            API_KEY => $apiKey
        ]);

        $processedRecords = 0;
        $totalResults = 1;
        $CVE_Records = [];

        // When too many records are present they must be retrieved through multiple requests
        do {
            // Set page index
            $NVD_Connection->setUrlParams([START_INDEX => $processedRecords]);

            // Get CVE records from NVD
            $records = $NVD_Connection->launchRequest();

            // If a request returned null abort
            if (is_null($records)) { break; }

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
                    $descriptions[$description['lang']] = str_replace("'", "\'", $description['value']);
                }

                // Configuration(s)
                $configurations = [];

                if (isset($record['configurations'])) {

                    foreach($record['configurations'] as $vendor_configs) {

                        $cpeMatches = $vendor_configs['nodes'][0]['cpeMatch'];

                        foreach($cpeMatches as $cpeMatch) {
    
                            $configuration = $cpeMatch['criteria'];

                            // Add new configuration
                            self::processNewConfiguration($configurations, $configuration);
                        }
                    }

                    // Clear empty configuration(s)
                    self::clearEmptyConfigurations($configurations);
                }

                // CVSS Metrics
                $base_score = null;
                $exploit_score = null;
                $impact_score = null;

                if (isset($record['metrics'])) {

                    $main_metrics = array_values($record['metrics'])[0][0];

                    $base_score     = $main_metrics['cvssData']['baseScore'];
                    $exploit_score  = $main_metrics['exploitabilityScore'];
                    $impact_score   = $main_metrics['impactScore'];
                }

                // Vulnerability information
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
     * Process vulnerability configuration and add it to known configurations
     * 
     * @since 1.0.0
     * 
     * @param array     configurations      List of known configurations
     * @param string    configuration       New configuration to process
     * 
     * @return void
     */
    private static function processNewConfiguration(&$configurations, $configuration) {

        $CPE = new PluginNvdCpe($configuration);

        $attributes = $CPE->attributes;

        $vendor     = $attributes[CPE_VENDOR];
        $product    = $attributes[CPE_PRODUCT];
        $update     = $attributes[CPE_UPDATE];
        $edition    = $attributes[CPE_SW_EDTION];
        $software   = $attributes[CPE_TARGET_SW];
        $hardware   = $attributes[CPE_TARGET_HW];

        if (!array_key_exists($vendor, $configurations)) {
            $configurations[$vendor] = [];
        }

        if (!array_key_exists($product, $configurations[$vendor])) {
            $configurations[$vendor][$product] = array(
                CPE_UPDATE => [],
                CPE_SW_EDTION => [],
                CPE_TARGET_SW => [],
                CPE_TARGET_HW => []
            );
        }

        PluginNvdCpe::addTermToAttributeList($configurations[$vendor][$product][CPE_UPDATE], $update);
        PluginNvdCpe::addTermToAttributeList($configurations[$vendor][$product][CPE_SW_EDTION], $edition);
        PluginNvdCpe::addTermToAttributeList($configurations[$vendor][$product][CPE_TARGET_SW], $software);
        PluginNvdCpe::addTermToAttributeList($configurations[$vendor][$product][CPE_TARGET_HW], $hardware);
    }

    /**
     * Delete configurations with no attributes set
     * 
     * @since 1.0.0
     * 
     * @param array     configurations      List of known configurations
     * 
     * @return void
     */
    private static function clearEmptyConfigurations(&$configurations) {

        foreach ($configurations as $vendor => $products) {
            foreach ($products as $product => $configuration) {

                $empty = empty(array_filter($configuration, function($attribute){
                    return !empty($attribute);
                }));

                if ($empty) {
                    unset($configurations[$vendor][$product]);
                }
            }

            if (empty($configurations[$vendor])) {
                unset($configurations[$vendor]);
            }
        }
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

        return PluginNvdDatabaseutils::pushResToArray($res, 'softwareversions_id');
    }

    /**
     * Queries the GLPI database and returns the data of all installed operating system versions
     * that the plugin is able to recognize.
     * 
     * Current suported Operating Systems are:
     * -Windows: xp, vista, 7, 10, 11
     * -Windows Server
     * -Debian
     * -Ubuntu
     * -Redhat
     * -MacOS
     * 
     * @since 1.0.0
     * 
     * @return array    Array of installed OS versions
     */
    private static function requestAllOSInstallations() {

        global $DB;

        /***********************************************************************************************
         * Request all operating system installations on the devices managed by GLPI
         * 
         *  SELECT operatingsystems_id, operatingsystemversions_id, operatingsystemkernelversions_id,
         *      operatingsystemservicepacks_id
         *  FROM glpi_items_operatingsystems
         *  GROUP BY operatingsystems_id, operatingsystemversions_id, operatingsystemkernelversions_id, 
         *      operatingsystemservicepacks_id 
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['operatingsystems_id', 'operatingsystemversions_id', 'operatingsystemkernelversions_id', 'operatingsystemservicepacks_id'],
                             'FROM' => 'glpi_items_operatingsystems',
                             'GROUPBY' => ['operatingsystems_id', 'operatingsystemversions_id', 'operatingsystemkernelversions_id', 'operatingsystemservicepacks_id']]);

        $OSInstalations = [];
        
        foreach ($res as $id => $row) {
            
            [$name, $version, $kernel, $kernelVersion, $servicePack] = PluginNvdDatabaseutils::requestOSdata($row);

            $installationData = PluginNvdCpe::getOSInstallationData($name, $version, $kernel, $kernelVersion, $servicePack);

            if (!is_null($installationData)) {

                $OSInstalations[] = $installationData;
            }
        }

        return $OSInstalations;
    }

    /**
     * Queries the GLPI database and returns:
     * -if $table == glpi_plugin_nvd_vulnerable_software_versions:
     *      -The IDs of all known vulnerable software versions if $column == 'softwareversions_id'
     *      -The IDs of all known vulnerabilities associated with some software versions if $column == 'vuln_id'
     * 
     * -if $table == glpi_plugin_nvd_vulnerable_system_versions:
     *      -The configurations of all known vulnerable operating system versions if $column == 'configuration'
     *      -The IDs of all known vulnerabilities associated with some operating system version if $column == 'vuln_id'
     * 
     * @since 1.0.0
     * 
     * @param string $table     Name of the table to query on the GLPI database
     * @param string $column    Name of the column to get from the specified table
     * 
     * @return array    Array of IDs
     */
    private static function requestAllVulnerableVersions($table, $column) {

        global $DB;

         /***********************************************************************************************
         * Request all known vulnerable software/system versions
         * 
         *  SELECT DISTINCT $column
         *  FROM $table 
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => $column,
                             'DISTINCT' => true,
                             'FROM' => $table]);

        return PluginNvdDatabaseutils::pushResToArray($res, $column);
    }

    /**
     * Removes vulnearable software/OS versions no longer present on any device managed by GLPI
     * 
     * @since 1.0.0
     * 
     * @param array $versionsToRemove    Software/OS versions to remove from vulnerable version tables
     * 
     * @return void
     */
    private static function removeOldVulnerableVersions($versionsToRemove, $table, $column) {

        global $DB;

        if($versionsToRemove) {

            /***********************************************************************************************
             * Remove all vulnerable versions no longer installed on any device
             * 
             *  DELETE FROM $table
             *  WHERE $conlumn IN $versionsToRemove
             **********************************************************************************************/
            $DB->delete(
                $table, [
                    $column => $versionsToRemove
                ]
            );
        }
    }

    /**
     * Queries the GLPI database and returns a CVE ID for every vulnerability associated with a given software/OS version
     * 
     * @since 1.0.0
     * 
     * @param string/int    $version_id         ID of the software version / OS configuration for the request
     * @param string        $version_table      Table that stores vulnerable versions
     * @param string        $version_column     Column that serves as the version/configuration ID
     * 
     * @return array    Array of vulnerability IDs
     */
    private static function getVersionCVEs($version_id, $version_table, $version_column) {

        global $DB;

        /***********************************************************************************************
         * Request all vulnerabilities associated with a given software/OS version
         * 
         *  SELECT cve_id 
         *  FROM glpi_plugin_nvd_vulnerabilities
         *  INNER JOIN $version_table
         *   ON glpi_plugin_nvd_vulnerabilities.id = $version_table.vuln_id
         *  WHERE $version_column = $version_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'cve_id',
                             'FROM' => 'glpi_plugin_nvd_vulnerabilities',
                             'INNER JOIN' => [$version_table => ['FKEY' => ['glpi_plugin_nvd_vulnerabilities' => 'id',
                                                                            $version_table => 'vuln_id']]] ,
                             'WHERE' => [$version_column => $version_id]]);

        return PluginNvdDatabaseutils::pushResToArray($res, 'cve_id');
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

        return PluginNvdDatabaseutils::pushResToArray($res, 'id', 'cve_id');
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

        $vendor_associations = PluginNvdDatabaseutils::pushResToArray($res, 'vendor_name', 'softwares_id');
        $product_associations = PluginNvdDatabaseutils::pushResToArray($res, 'product_name', 'softwares_id');

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
     * @param array     $knownCVEs                  List of known vulnerabilities and their IDs on the database
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

                $update     = (empty($configuration[CPE_UPDATE]))    ? null : implode(' ', $configuration[CPE_UPDATE]);
                $edition    = (empty($configuration[CPE_SW_EDTION])) ? null : implode(' ', $configuration[CPE_SW_EDTION]);
                $target_sw  = (empty($configuration[CPE_TARGET_SW])) ? null : implode(' ', $configuration[CPE_TARGET_SW]);
                $target_hw  = (empty($configuration[CPE_TARGET_HW])) ? null : implode(' ', $configuration[CPE_TARGET_HW]);

                /***********************************************************************************************
                 * Insert new vulnerability configuration into glpi database
                 * 
                 *  INSERT INTO glpi_plugin_nvd_vulnerability_configurations
                 *  (vuln_id, vendor_name, product_name, update, edition, target_sw, target_hw) 
                 *  VALUES ($vuln_id, $vendor, $product, $update, $edition, $target_sw, $target_hw)
                 **********************************************************************************************/
                $DB->insert(
                    'glpi_plugin_nvd_vulnerability_configurations', [
                        'vuln_id' => $vuln_id,
                        'vendor_name' => $vendor,
                        'product_name' => $product,
                        'update' => $update,
                        'edition' => $edition,
                        'target_sw' => $target_sw,
                        'target_hw' => $target_hw
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
     * @param string    $vuln_versions_table                Table in the GLPI database that stores vulnerable versions
     * @param string    $vuln_version_column                Column of given table that stores the ID for the version
     * 
     * @return void
     */
    private static function insertNewVersionVulnerabilities($missingVersionVulnerabilities, $version_id, $knownCVEs, $vuln_versions_table, $vuln_version_column) {

        global $DB;

        foreach ($missingVersionVulnerabilities as $CVE_ID) {

            $vulnID = $knownCVEs[$CVE_ID];

            /***********************************************************************************************
             * Insert new vulnerable software/OS version into GLPI database
             * 
             *  INSERT INTO $vuln_versions_table
             *  (vuln_id, $vuln_version_column) VALUES ($vulnID, $version_id)
             **********************************************************************************************/
            $DB->insert(
                $vuln_versions_table, [
                    'vuln_id' => $vulnID,
                    $vuln_version_column => $version_id
                ]
            );
        }
    }

    /**
     * Removes vulnerabilities no longer present on any device managed by GLPI
     * 
     * @since 1.0.0
     * 
     * @param array     $oldVulnerabilities     List of vulnerabilities to remove from the GLPI database
     * 
     * @return void
     */
    private static function removeVulnerabilities($oldVulnerabilities){

        global $DB;

        if ($oldVulnerabilities) {

            /***********************************************************************************************
             * Remove all vulnerable versions no longer installed on any device
             * 
             *  DELETE FROM glpi_plugin_nvd_vulnerabilities
             *  WHERE id IN $oldVulnerabilities
             **********************************************************************************************/
            $DB->delete(
                'glpi_plugin_nvd_vulnerabilities', [
                    'id' => $oldVulnerabilities
                ]
            );

            /***********************************************************************************************
             * Remove all descriptions for the removed vulnerabilities
             * 
             *  DELETE FROM glpi_plugin_nvd_vulnerability_descriptions
             *  WHERE vuln_id IN $oldVulnerabilities
             **********************************************************************************************/
            $DB->delete(
                'glpi_plugin_nvd_vulnerability_descriptions', [
                    'vuln_id' => $oldVulnerabilities
                ]
            );

            /***********************************************************************************************
             * Remove all configurations for the removed vulnerabilities
             * 
             *  DELETE FROM glpi_plugin_nvd_vulnerability_configurations
             *  WHERE vuln_id IN $oldVulnerabilities
             **********************************************************************************************/
            $DB->delete(
                'glpi_plugin_nvd_vulnerability_configurations', [
                    'vuln_id' => $oldVulnerabilities
                ]
            );
        }
    }
}

?>