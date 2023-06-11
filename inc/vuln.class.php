<?php

class PluginNvdVuln extends CommonDBTM {

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
     * @param CommonGLPI $item
     * @param int        $withtemplate
     *
     * @return boolean
     */
    function getTabNameForItem(CommonGLPI $item, $withtemplate=0) {

        $totalVulnerabilities = 0;
        
        switch($item::getType()) {

            case Software::getType():

                $totalVulnerabilities = self::countForSoftware($item);
                break;

            case Computer::getType():
            case Phone::getType():

                [$totalVulnerabilities, $NsoftwareVulns, $NsystemVulns] = self::countForDevice($item);
                break;

            default:

                [$totalVulnerabilities, $NsoftwareVulns, $NsystemVulns] = self::countForDashboard();
        }
        
        return self::createTabEntry(__('Vulnerabilities'), $totalVulnerabilities);
    }

    /**
     * Count number of vulnerabilities related to a given software
     *
     * @since 1.0.0
     *
     * @param Software $item        Software item to look vulnerabilities for
     *
     * @return int                  Number of vulnerabilities found
     */
    private static function countForSoftware(Software $item) {

        global $DB;

        /***********************************************************************************************
         * Request vulnerabilities to which the given software's different versions are vulnerable
         * 
         *  SELECT vuln_id
         *  FROM glpi_plugin_nvd_vulnerable_software_versions 
         *  INNER JOIN glpi_softwareversions 
         *  ON glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id = glpi_softwareversions.id
         *  WHERE softwares_id = $item->getID()
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'vuln_id',
                             'FROM' => 'glpi_plugin_nvd_vulnerable_software_versions',
                             'INNER JOIN' => ['glpi_softwareversions' => ['FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
                                                                                     'glpi_softwareversions' => 'id']]] ,
                             'WHERE' => ['softwares_id' => $item->getID()],
                             'GROUPBY' => 'vuln_id']);

        return $res->numrows();
    }

    /**
     * Count number of vulnerabilities related to a given device
     *
     * @since 1.0.0
     *
     * @param CommonGLPI $item      Device item to look vulnerabilities for
     *
     * @return array                Array containing the number of found vulnerabilities and the division between software and system vulnerabilities
     */
    private static function countForDevice(CommonGLPI $item) {

        global $DB;

        /***********************************************************************************************
         * Request vulnerabilities to which the given device's different programs are vulnerable
         * 
         *  SELECT vuln_id
         *  FROM glpi_plugin_nvd_vulnerable_software_versions 
         *  INNER JOIN glpi_items_softwareversions 
         *  ON glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id = 
         *     glpi_items_softwareversions.softwareversions_id
         *  WHERE items_id' = $item->getID() AND 'itemtype' = $item->getType()
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'vuln_id',
                                         'FROM' => 'glpi_plugin_nvd_vulnerable_software_versions',
                                         'INNER JOIN' => ['glpi_items_softwareversions' => ['FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
                                                                                                     'glpi_items_softwareversions' => 'softwareversions_id']]],
                                         'WHERE' => ['items_id' => $item->getID(), 'itemtype' => $item->getType()],
                                         'GROUPBY' => 'vuln_id']);

        $NsoftwareVulns = $res->numrows();

        $softwareVulns = PluginNvdDatabaseutils::pushResToArray($res, 'vuln_id');

        /***********************************************************************************************
         * Request operating system version for the given device
         * 
         *  SELECT operatingsystems_id, operatingsystemversions_id, operatingsystemkernelversions_id,
         *      operatingsystemservicepacks_id
         *  FROM glpi_items_operatingsystems
         *  WHERE items_id' = $item->getID() AND 'itemtype' = $item->getType()
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['operatingsystems_id', 'operatingsystemversions_id', 'operatingsystemkernelversions_id', 'operatingsystemservicepacks_id'],
                             'FROM' => 'glpi_items_operatingsystems',
                             'WHERE' => ['items_id' => $item->getID(), 'itemtype' => $item->getType()]]);

        if ($res->numrows() == 0) { return [$NsoftwareVulns, $NsoftwareVulns, 0]; }

        [$name, $version, $kernel, $kernelVersion, $servicePack] = PluginNvdDatabaseutils::requestOSdata($res->current());

        $installationData = PluginNvdCpe::getOSInstallationData($name, $version, $kernel, $kernelVersion, $servicePack);

        if (is_null($installationData)) { return [$NsoftwareVulns, $NsoftwareVulns, 0]; }

        $configuration = $installationData['configuration'];

        /***********************************************************************************************
         * Request every operating system vulnerability associated with the given device
         * 
         *  SELECT vuln_id 
         *  FROM glpi_plugin_nvd_vulnerable_system_versions
         *  WHERE system_configuration = $configuration
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'vuln_id',
                                         'FROM' => 'glpi_plugin_nvd_vulnerable_system_versions',
                                         'WHERE' => ['system_configuration' => $configuration]]);

        $NsystemVulns = $res->numrows();

        $systemVulns = PluginNvdDatabaseutils::pushResToArray($res, 'vuln_id');

        $totalVulns = count(array_unique(array_merge($softwareVulns, $systemVulns)));

        return [$totalVulns, $NsoftwareVulns, $NsystemVulns];
    }

    /**
     * Count total number of vulnerabilities
     *
     * @since 1.0.0
     *
     * @return array Array containing the number of found vulnerabilities and the division between software and system vulnerabilities
     */
    private static function countForDashboard() {

        global $DB;

        /***********************************************************************************************
         * Request every software vulnerability registered
         * 
         *  SELECT vuln_id 
         *  FROM glpi_plugin_nvd_vulnerable_software_versions
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'vuln_id',
                                         'FROM' => 'glpi_plugin_nvd_vulnerable_software_versions',
                                         'GROUPBY' => 'vuln_id']);

        $NsoftwareVulns = $res->numrows();
        
        $softwareVulns = PluginNvdDatabaseutils::pushResToArray($res, 'vuln_id');

        /***********************************************************************************************
         * Request every operating system vulnerability registered
         * 
         *  SELECT vuln_id 
         *  FROM glpi_plugin_nvd_vulnerable_system_versions
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'vuln_id',
                                         'FROM' => 'glpi_plugin_nvd_vulnerable_system_versions',
                                         'GROUPBY' => 'vuln_id']);

        $NsystemVulns = $res->numrows();

        $systemVulns = PluginNvdDatabaseutils::pushResToArray($res, 'vuln_id');

        $totalVulns = count(array_unique(array_merge($softwareVulns, $systemVulns)));

        return [$totalVulns, $NsoftwareVulns, $NsystemVulns];
    }

    /**
     * Display tab content for given item
     *
     * @since 1.0.0
     *
     * @param CommonGLPI $item       Item for which to display vulnerabilities
     * @param int $tabnum
     * @param int $withtemplate
     *
     * @return boolean
     */
    static function displayTabContentForItem(CommonGLPI $item, $tabnum=1, $withtemplate=0) {

        switch($item::getType()) {

            case Software::getType():

                self::displayForSoftware($item);
                break;

            case Computer::getType():
            case Phone::getType():

                [$totalVulnerabilities, $NsoftwareVulns, $NsystemVulns] = self::countForDevice($item);
                self::displayForDevice($item, $NsoftwareVulns, $NsystemVulns);
                break;

            default:

                [$totalVulnerabilities, $NsoftwareVulns, $NsystemVulns] = self::countForDashboard();
                self::displayForDashboard($NsoftwareVulns, $NsystemVulns);
        }
        
        return true;
    }

    /**
     * Display tab content for given Software item
     *
     * @since 1.0.0
     *
     * @param Software $item       Software item for which to display vulnerabilities
     *
     * @return void
     */
    private static function displayForSoftware(Software $item) {

        global $DB, $CFG_GLPI;

        /***********************************************************************************************
         * Request vulnerabilities to which the given software's different versions are vulnerable
         * 
         *  SELECT vuln_id AS VULN_ID, 
         *   GROUP_CONCAT(glpi_softwareversions.id, ':', glpi_softwareversions.name) AS version
         *  FROM glpi_plugin_nvd_vulnerable_software_versions 
         *  INNER JOIN glpi_softwareversions 
         *  ON glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id = glpi_softwareversions.id
         *  WHERE softwares_id = $item->getID()
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => [
                                'vuln_id AS VULN_ID',
                                new QueryExpression("GROUP_CONCAT(`glpi_softwareversions`.`id`, ':', `glpi_softwareversions`.`name`) AS `version`")
                             ],
                             'FROM' => 'glpi_plugin_nvd_vulnerable_software_versions',
                             'INNER JOIN' => ['glpi_softwareversions' => ['FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
                                                                                     'glpi_softwareversions' => 'id']]] ,
                             'WHERE' => ['softwares_id' => $item->getID()],
                             'GROUPBY' => 'vuln_id']);
        
        $vulnerabilities = [];

        foreach ($res as $id => $row) {

            $versions = explode(',', $row['version']);

            $instances = [];

            foreach ($versions as $version) {

                [$id, $name] = explode(':', $version);

                $instances[] = '<a href="' . "{$CFG_GLPI['root_doc']}/front/softwareversion.form.php?id=" . $id . '">' . $name . '</a>';
            }

            $vulnerabilities[$row['VULN_ID']] = implode(', ', $instances);
        }

        /***********************************************************************************************
         * Request CPE vendor and product name associated with given software
         * 
         *  SELECT vendor_name, product_name
         *  FROM glpi_plugin_nvd_cpe_software_associations 
         *  WHERE softwares_id = $item->getID()
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['vendor_name', 'product_name'],
                                'FROM' => 'glpi_plugin_nvd_cpe_software_associations',
                                'WHERE' => ['softwares_id' => $item->getID()]]);

        if ($res->numrows() == 0) { return; }

        $row = $res->current();
        $filters = array(
            'vendor_name' => $row['vendor_name'], 
            'product_name' => $row['product_name']
        );

        //Request information on the obtained CVE records 
        $res = self::requestVulnerabilities(array_keys($vulnerabilities));

        //Display list of vulnerabilities associated with given software
        echo self::displayVulnerabilityList($res, $vulnerabilities, __('Versions'), $filters);
    }

    /**
     * Display tab content for given Device item
     *
     * @since 1.0.0
     *
     * @param CommonGLPI $item      Device item for which to display vulnerabilities
     * @param int $NsoftwareVulns   Number of software vulnerabilities
     * @param int $NsystemVulns     Number of operating system vulnerabilities
     *
     * @return void
     */
    private static function displayForDevice(CommonGLPI $item, $NsoftwareVulns, $NsystemVulns) {

        global $DB, $CFG_GLPI;

        /***************************\
        |* Software Vulnerabilities |
        \***************************/

        /***********************************************************************************************
         * Request vulnerabilities to which the given device's different programs are vulnerable
         * 
         *  SELECT vuln_id AS VULN_ID, 
         *         GROUP_CONCAT(glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id) AS version
         *  FROM glpi_plugin_nvd_vulnerable_software_versions 
         *  INNER JOIN glpi_items_softwareversions 
         *  ON glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id = 
         *     glpi_items_softwareversions.softwareversions_id
         *  WHERE items_id' = $item->getID() AND 'itemtype' = $item->getType()
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => [
                    'vuln_id AS VULN_ID',
                    new QueryExpression("GROUP_CONCAT(`glpi_plugin_nvd_vulnerable_software_versions`.`softwareversions_id`) AS `version`")
                ],
                'FROM' => 'glpi_plugin_nvd_vulnerable_software_versions',
                'INNER JOIN' => ['glpi_items_softwareversions' => ['FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
                                                                              'glpi_items_softwareversions' => 'softwareversions_id']]],
                'WHERE' => ['items_id' => $item->getID(), 'itemtype' => $item->getType()],
                'GROUPBY' => 'vuln_id']);

        $vulnerabilities = [];

        foreach ($res as $id => $row) {

            /***********************************************************************************************
             * Request IDs and names from programs that are vulnerable to the obtained vulnerabilities
             * 
             *  SELECT DISTINCT glpi_softwares.id, glpi_softwares.name
             *  FROM glpi_softwares 
             *  INNER JOIN glpi_softwareversions 
             *  ON glpi_softwares.id = glpi_softwareversions.softwares_id
             *  WHERE glpi_softwareversions.id IN explode(',', $row['version'])
             **********************************************************************************************/
            $res_2 = $DB->request(['SELECT' => ['glpi_softwares.id', 'glpi_softwares.name'],
                                 'DISTINCT' => true,
                                 'FROM' => 'glpi_softwares',
                                 'INNER JOIN' => ['glpi_softwareversions' => ['FKEY' => ['glpi_softwares' => 'id',
                                                                                         'glpi_softwareversions' => 'softwares_id']]],
                                 'WHERE' => ['glpi_softwareversions.id' => explode(',', $row['version'])]]);

            $programs = [];

            //Transform names and IDs to liks to vulnerable programs in GLPI
            foreach ($res_2 as $id_2 => $row_2) {
                $programs[] = '<a href="' . "{$CFG_GLPI['root_doc']}/front/software.form.php?id=" . $row_2['id'] . '">' . $row_2['name'] . '</a>';
            }
            
            $vulnerabilities[$row['VULN_ID']] = implode(',', $programs);
        }

        //Request information on the obtained CVE records 
        $res = self::requestVulnerabilities(array_keys($vulnerabilities));

        //Display list of software vulnerabilities associated with given device
        $softwareList = self::displayVulnerabilityList($res, $vulnerabilities, __('Programs'));

        /**********************************\
        |* Operating Sytem Vulnerabilities |
        \**********************************/

        $vulnerabilities = [];
        $filters = [];

        /***********************************************************************************************
         * Request operating system version for the given device
         * 
         *  SELECT operatingsystems_id, operatingsystemversions_id, operatingsystemkernelversions_id,
         *      operatingsystemservicepacks_id
         *  FROM glpi_items_operatingsystems
         *  WHERE items_id' = $item->getID() AND 'itemtype' = $item->getType()
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['operatingsystems_id', 'operatingsystemversions_id', 'operatingsystemkernelversions_id', 'operatingsystemservicepacks_id'],
                                          'FROM' => 'glpi_items_operatingsystems',
                                          'WHERE' => ['items_id' => $item->getID(), 'itemtype' => $item->getType()]]);

        if ($res->numrows() == 1) { 

            [$name, $version, $kernel, $kernelVersion, $servicePack] = PluginNvdDatabaseutils::requestOSdata($res->current());

            $installationData = PluginNvdCpe::getOSInstallationData($name, $version, $kernel, $kernelVersion, $servicePack);

            if (!is_null($installationData)) {

                $filters = array(
                    'vendor_name' => $installationData[CPE_VENDOR], 
                    'product_name' => $installationData[CPE_PRODUCT]
                );

                $configuration = $installationData['configuration'];

                /***********************************************************************************************
                * Request every operating system vulnerability associated with the given device
                * 
                *  SELECT vuln_id 
                *  FROM glpi_plugin_nvd_vulnerable_system_versions
                *  WHERE system_configuration = $configuration
                **********************************************************************************************/
                $res = $DB->request(['SELECT' => 'vuln_id',
                'FROM' => 'glpi_plugin_nvd_vulnerable_system_versions',
                'WHERE' => ['system_configuration' => $configuration]]);

                $vulnerabilities = PluginNvdDatabaseutils::pushResToArray($res, 'vuln_id');
            }
        }

        //Request information on the obtained CVE records 
        $res = self::requestVulnerabilities($vulnerabilities);

        // Display list of OS vulnerabilities
        $systemList = self::displayVulnerabilityList($res, $vulnerabilities, NULL, $filters);;

        // Display both software and system vulnerabilities organized with nav tabs
        self::displayNavTabs($softwareList, $NsoftwareVulns, $systemList, $NsystemVulns);
    }

    /**
     * Display tab content on central dashboard
     *
     * @since 1.0.0
     * 
     * @param int $NsoftwareVulns   Number of software vulnerabilities
     * @param int $NsystemVulns     Number of operating system vulnerabilities
     *
     * @return void
     */
    private static function displayForDashboard($NsoftwareVulns, $NsystemVulns){

        global $DB, $CFG_GLPI;

        /***************************\
        |* Software Vulnerabilities |
        \***************************/

        /***********************************************************************************************
         * Request every vulnerability registered and the devices associated with it
         * 
         *  SELECT vuln_id AS VULN_ID, 
         *       GROUP_CONCAT(DISTINCT itemtype, ':', items_id ORDER BY itemtype, items_id) AS instances
         *  FROM glpi_plugin_nvd_vulnerable_software_versions, glpi_items_softwareversions
         *  WHERE glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id = 
         *        glpi_items_softwareversions.softwareversions_id
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => [
                    'vuln_id AS VULN_ID',
                    new QueryExpression("GROUP_CONCAT(DISTINCT `itemtype`, ':', `items_id` ORDER BY `itemtype`, `items_id`) AS instances")
                ],
                'FROM' => ['glpi_plugin_nvd_vulnerable_software_versions', 'glpi_items_softwareversions'],
                'FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
                           'glpi_items_softwareversions' => 'softwareversions_id'],
                'GROUPBY' => 'vuln_id']);

        $vulnerabilities = [];

        foreach ($res as $id => $row) {

            $instances = explode(',', $row['instances']);
            $instance_IDs = [];

            // Sort every device into it's corresponding category
            foreach ($instances as $id => $device) {

                [$item_type, $item_id] = explode(':', $device);
                $instance_IDs[strtolower($item_type)][] = $item_id;
            }

            // Request device names from corresponding tables
            foreach ($instance_IDs as $item_type => $IDs) {

                $table = 'glpi_' . $item_type . 's';

                /***********************************************************************************************
                 * Request device names for the device IDs associated with a vulnerability
                 * 
                 *  SELECT name
                 *  FROM 'glpi_' . $item_type . 's'
                 *  WHERE id IN $IDs
                 **********************************************************************************************/
                $res_2 = $DB->request(['SELECT' => new QueryExpression("GROUP_CONCAT(`name` ORDER BY `id`) AS names"),
                                       'FROM' => $table,
                                       'WHERE' => ['id' => $IDs]]);

                //Associate device types and names with their corresponding name
                $instance_IDs[$item_type] = array_combine($instance_IDs[$item_type], explode(',', $res_2->current()['names']));
            }

            $instances = [];

            // Transform names and IDs to liks to vulnerable devices in GLPI
            foreach ($instance_IDs as $item_type => $ID_names) {
                foreach ($ID_names as $ID => $name) {
                    $instances[] = '<a href="' . "{$CFG_GLPI['root_doc']}/front/$item_type.form.php?id=" . $ID . '">' . $name . '</a>';
                }
            }

            $vulnerabilities[$row['VULN_ID']] = implode(',', $instances);
        }

        //Request information on the obtained CVE records 
        $res = self::requestVulnerabilities(array_keys($vulnerabilities));

        //Display list of software vulnerabilities
        $softwareList = self::displayVulnerabilityList($res, $vulnerabilities, __('Devices'));

        /**********************************\
        |* Operating Sytem Vulnerabilities |
        \**********************************/

        /***********************************************************************************************
         * Request every operating system version and the devices associated with it
         * 
         *  SELECT items_id, itemtype, operatingsystems_id, operatingsystemversions_id, 
         *      operatingsystemkernelversions_id, operatingsystemservicepacks_id
         *  FROM glpi_items_operatingsystems
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['items_id', 'itemtype', 'operatingsystems_id', 'operatingsystemversions_id',
                                          'operatingsystemkernelversions_id', 'operatingsystemservicepacks_id'],
                                          'FROM' => 'glpi_items_operatingsystems']);

        $deviceConfigurations = [];

        foreach ($res as $id => $row) {

            $item_type = $row['itemtype'];
            $ID = $row['items_id'];

            [$name, $version, $kernel, $kernelVersion, $servicePack] = PluginNvdDatabaseutils::requestOSdata($row);

            $installationData = PluginNvdCpe::getOSInstallationData($name, $version, $kernel, $kernelVersion, $servicePack);

            if (!is_null($installationData)) {

                $configuration = $installationData['configuration'];

                $table = 'glpi_' . $item_type . 's';

                /***********************************************************************************************
                 * Request device names for every device
                 * 
                 *  SELECT name
                 *  FROM 'glpi_' . $item_type . 's'
                 *  WHERE id = $ID
                 **********************************************************************************************/
                $res_2 = $DB->request(['SELECT' => 'name',
                                    'FROM' => $table,
                                    'WHERE' => ['id' => $ID]]);

                $deviceName = ($res_2->numrows() == 1) ? $res_2->current()['name'] : 'UNNAMED_DEVICE';

                $deviceConfigurations[$configuration][] = '<a href="' . "{$CFG_GLPI['root_doc']}/front/$item_type.form.php?id=" . $ID . '">' . $deviceName . '</a>';
            }
        }

        /***********************************************************************************************
         * Request every vulnerability registered and the configurations associated with it
         * 
         *  SELECT vuln_id AS VULN_ID, GROUP_CONCAT(system_configuration) AS configurations
         *  FROM glpi_plugin_nvd_vulnerable_system_versions
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['vuln_id AS VULN_ID', new QueryExpression("GROUP_CONCAT(`system_configuration`) AS configurations")],
                             'FROM' => 'glpi_plugin_nvd_vulnerable_system_versions',
                             'GROUPBY' => 'vuln_id']);

        $vulnerabilities = [];

        foreach ($res as $id => $row) {

            $configurations = explode(',', $row['configurations']);

            $devices = [];

            foreach ($configurations as $configuration) {
                
                $devices = array_merge($devices, $deviceConfigurations[$configuration]);
            }

            $vulnerabilities[$row['VULN_ID']] = implode(', ', $devices);
        }

        //Request information on the obtained CVE records 
        $res = self::requestVulnerabilities(array_keys($vulnerabilities));

        // Display list of OS vulnerabilities
        $systemList = self::displayVulnerabilityList($res, $vulnerabilities, __('Devices'));;

        // Display both software and system vulnerabilities organized with nav tabs
        self::displayNavTabs($softwareList, $NsoftwareVulns, $systemList, $NsystemVulns);
    }

    /**
     * Request list of vulnerabilities for the given item
     *
     * @since 1.0.0
     *
     * @param array $vulnerabilityIDs       IDs of vulnerabilities to query
     *
     * @return DBmysqlIterator
     */
    private static function requestVulnerabilities($vulnerabilityIDs) {

        if (!$vulnerabilityIDs) { return []; }

        global $DB;

        /***********************************************************************************************
        * Request information on the obtained CVE records 
        * 
        *  SELECT *
        *  FROM glpi_plugin_nvd_vulnerabilities
        *  WHERE id IN array_keys($vulnerabilities)
        *  ORDER BY severity DESC
        **********************************************************************************************/
        $res = $DB->request(['FROM' => 'glpi_plugin_nvd_vulnerabilities',
                'WHERE' => ['id' => $vulnerabilityIDs],
                'ORDER' => 'base_score DESC']);

        return $res;
    }

    /**
     * Request list of description for a given vulnerability
     *
     * @since 1.0.0
     *
     * @param int $vulnID       ID of vulnerabilities to query
     *
     * @return DBmysqlIterator
     */
    private static function requestDescriptions($vulnID) {

        global $DB;

        /***********************************************************************************************
        * Request descriptions for a CVE record
        * 
        *  SELECT *
        *  FROM glpi_plugin_nvd_vulnerability_descriptions
        *  WHERE vuln_id = $vulnID
        **********************************************************************************************/
        $res = $DB->request(['FROM' => 'glpi_plugin_nvd_vulnerability_descriptions',
                'WHERE' => ['vuln_id' => $vulnID]]);

        return $res;
    }

    /**
     * Request list of configurations for a given vulnerability
     *
     * @since 1.0.0
     *
     * @param int   $vulnID         ID of vulnerabilities to query
     * @param array $filters        Optional query filters
     *
     * @return DBmysqlIterator
     */
    private static function requestConfigurations($vulnID, $filters) {

        global $DB;

        /***********************************************************************************************
        * Request configurations for a CVE record
        * 
        *  SELECT *
        *  FROM glpi_plugin_nvd_vulnerability_configurations
        *  WHERE vuln_id = $vulnID AND $filters
        **********************************************************************************************/
        $condition = ['vuln_id' => $vulnID];

        if (!is_null($filters)) {
            $condition = array_merge($condition, $filters);
        }

        $res = $DB->request(['FROM' => 'glpi_plugin_nvd_vulnerability_configurations',
                'WHERE' => $condition ]);

        return $res;
    }

    /**
     * Display list of vulnerabilities for the given item
     *
     * @since 1.0.0
     *
     * @param DBmysqlIterator   $DBQueryResult          Result of the CVE query
     * @param array             $vulnerableInstances    Array of vulnerability IDs and their instances
     * @param bool              $is_software            Whether or not to treat the instances as software versions or programs 
     *
     * @return string           
     */
    private static function displayVulnerabilityList($DBQueryResult, $vulnerableInstances, $instance_name, $filters=NULL) {

        // If no vulnerabilities are found do not display anything
        if (!$vulnerableInstances) { return ''; }

        $table = '<table class="center vuln-table">';

        if (!is_null($instance_name)) {

            $table .= '<colgroup><col width="10%"/><col width="5%"/><col width="15%"/><col width="5%"/><col width="55%"/><col width="10%"/></colgroup>';
        
        } else {

            $table .= '<colgroup><col width="15%"/><col width="10%"/><col width="15%"/><col width="5%"/><col width="55%"/></colgroup>';
        }
        
        $table .=   '<tr>';
        $table .=   '<th class="centered">' . __('Severity') . '</th>';
        $table .=   '<th class="centered">' . __('Score') . '</th>';
        $table .=   '<th class="centered">CVE-ID</th>';
        $table .=   '<th class="centered">' . mb_chr(0x2755, 'UTF-8') . '</th>';
        $table .=   '<th class="centered">' . __('Description') . '</th>';
        $table .=   !is_null($instance_name) ? '<th class="centered">' . $instance_name . '</th>' : '';
        $table .=   '</tr>';

        foreach ($DBQueryResult as $id => $row) {

            $descriptions   = self::requestDescriptions($id);
            $description    = PluginNvdCverecord::getDescriptionForLanguage($descriptions);

            $configurations = self::requestConfigurations($id, $filters);
            $configuration_warning = PluginNvdCverecord::parseConfiguration($configurations, !is_null($filters));

            $table .= '<tr>';
            $table .= '<td class="centered">' . PluginNvdCverecord::getCvssScoreSeverity($row['base_score']) . '</td>';
            $table .= '<td class="centered">' . $row['base_score'] . '</td>';
            $table .= '<td class="centered"> <a href="' . PluginNvdCverecord::getCveNvdUrl($row['cve_id']) . '">' . $row['cve_id'] . '</a></td>';
            $table .= '<td class="centered" ' . $configuration_warning . '</td>';
            $table .= '<td class="justified">' . $description . '</td>';
            $table .= !is_null($instance_name) ? '<td class="centered">' . $vulnerableInstances[$id] . '</td>' : '';
            $table .= '</tr>';
        }

        $table .= '</table>';

        return $table;
    }

    /**
     * Display navigational tabs for software and operating system related vulnerabilities
     *
     * @since 1.0.0
     *
     * @return void
     */
    private static function displayNavTabs($softwareContent, $NsoftwareVulns, $systemContent, $NsystemVulns) {

        $out  = '<nav>';
        $out .= '<div class="nav nav-tabs" id="nav-tab" role="tablist">';
        $out .= '<button class="nav-link active" id="nav-software_vuln-tab" data-bs-toggle="tab" data-bs-target="#nav-software_vuln" type="button" role="tab" aria-controls="nav-software_vuln" aria-selected="true">';
        $out .= __('Software Vulnerabilities') . '<div style="text-indent:2em"><span class="badge" style="text-indent:0em">' . "$NsoftwareVulns" . '</span></div></button>';
        $out .= '<button class="nav-link" id="nav-system_vuln-tab" data-bs-toggle="tab" data-bs-target="#nav-system_vuln" type="button" role="tab" aria-controls="nav-system_vuln" aria-selected="false">';
        $out .= __('OS Vulnerabilities') . '<div style="text-indent:2em"><span class="badge" style="text-indent:0em">' . "$NsystemVulns" . '</span></div></button>';
        $out .= '</div>';
        $out .= '</nav>';
        $out .= '<div class="tab-content" id="nav-tabContent">';
        $out .= '<div class="tab-pane fade show active" id="nav-software_vuln" role="tabpanel" aria-labelledby="nav-software_vuln-tab">';
        $out .= "$softwareContent</div>";
        $out .= '<div class="tab-pane fade" id="nav-system_vuln" role="tabpanel" aria-labelledby="nav-system_vuln-tab">';
        $out .= "$systemContent</div>";
        $out .= '</div>';

        echo $out;
    }
}

?>