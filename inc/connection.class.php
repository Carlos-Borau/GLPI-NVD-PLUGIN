<?php

define('API_KEY',               'apiKey');
define('CPE_NAME',              'cpeName');
define('VULNERABLE',            'isVulnerable');
define('LAST_MOD_START_DATE ',  'lastModStartDate');
define('LAST_MOD_END_DATE ',    'lastModEndDate ');

class PluginNvdConnection {

    private static string $apiKey;

    private const baseRequestUrl    = "https://services.nvd.nist.gov/rest/json/cves/2.0/";
    private const baseCveUrl        = "https://nvd.nist.gov/vuln/detail/";

    private string $urlParams;

	static function setApiKey($apiKey) {
        /**
        * 
        * @todo Set API Key on DB
        */ 
		PluginNvdConnection::$apiKey = $apiKey;
	}

    static function getApiKey() {
        /**
        * 
        * @todo Get API Key on DB
        */ 
		return PluginNvdConnection::$apiKey;
    }

    static function getCveNvdUrl($CveID) {

        return self::baseCveUrl . $CveID;
    }

    public function setUrlParams($cpeName, $isVulnerable = False, $lastModDate = False) {

        $this->urlParams = CPE_NAME . '=' . $cpeName;

        if ($isVulnerable) {
            $this->urlParams .= '&' . VULNERABLE;
        }

        if ($lastModDate) {
            /**
            * 
            * @todo Get LAST_MOD_START_DATE from DB
            */ 

            //$lastModStartDate = ...;
            $lastModEndDate = date(c);

            //$this->urlParams .= '&' . LAST_MOD_START_DATE . '=' . $lastModStartDate;
            $this->urlParams .= '&' . LAST_MOD_END_DATE . '=' . $lastModEndDate;
        }
    }

    public function getCompleteUrl() {

        return self::baseRequestUrl . '?' . $this->urlParams;
    }

    public function requestNvdRecords() {

        /**
        * 
        * @todo Retrieve API key from DB
        */ 

        $url    = self::baseRequestUrl . '?' . $this->urlParams;
        $header = API_KEY . ': ' . self::$apiKey;

        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, $header);

        $output = curl_exec($ch);

        curl_close($ch);

        return json_decode($output, true);
    }

    public function getVulnFormatedTable($records) {

        $resultsPerPage     = $records['resultsPerPage'];
        $startIndex         = $records['startIndex'];
        $totalResults       = $records['totalResults'];
        $format             = $records['format'];
        $version            = $records['version'];
        $timestamp          = $records['timestamp'];
        $vulnerabilities    = $records['vulnerabilities'];

        echo 'Retrieved ' . $totalResults . ' records from NVD database <br>';

        $table =    '<table class="center">';
        $table .=   '<colgroup><col width="10%"/><col width="20%"/><col width="70%"/></colgroup>';
        $table .=   '<tr>';
        $table .=   '<th>CVE-ID</th>';
        $table .=   '<th>' . __('Publish Date') . '</th>';
        $table .=   '<th>' . __('Description') . '</th>';
        $table .=   '</tr>';

        foreach($vulnerabilities as $v) {

            $table .= '<tr>';

            $id             = $v['cve']['id'];
            $publishDate    = $v['cve']['published'];
            $descriptions   = [];

            foreach($v['cve']['descriptions'] as $d){
                $descriptions[$d['lang']] = $d['value'];
            }

            $table .= '<td>' . $id . '</td>';
            $table .= '<td>' . $publishDate . '</td>';
            $table .= '<td>' . $descriptions['en'] . '</td>';

            $table .= '</tr>';
        }

        $table .= '</table>';

        return $table;
    }

}

?>