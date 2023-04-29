<?php

class PluginNvdConnection {

    private string $baseRequestUrl;
    private array $urlHeaders;
    private array $urlParams;

    /**
     * Construct Connection headers and parameters
     * 
     * @since 1.0.0
     * 
     * @return void 
     */
    public function __construct($baseRequestUrl) {

        $this->baseRequestUrl = $baseRequestUrl;
        $this->urlHeaders = array();
        $this->urlParams = array();
    }

    /**
     * Assign values to URL parameters
     * 
     * @since 1.0.0
     * 
     * @param array $params     Associative array with values to assign to URL parameters
     * 
     * @return void 
     */
    public function setUrlParams(array $params) {

        foreach ($params as $param => $value) {
            $this->urlParams[$param] = $value; 
        }
    }

    /**
     * Assign values to request headers
     * 
     * @since 1.0.0
     * 
     * @param array $headers     Associative array with values to assign to request headers
     * 
     * @return void 
     */
    public function setUrlHeaders(array $headers) {

        foreach ($headers as $header => $value) {
            $this->UrlHeaders[$header] = $value; 
        }
    }

    /**
     * Returns Url with parameters
     * 
     * @since 1.0.0
     * 
     * @return string 
     */
    private function getCompleteUrl() {

        $completeUrl = $this->baseRequestUrl;

        if (count($this->urlParams) != 0) {

            $completeUrl .= '?';

            foreach ($this->urlParams as $parameter => $value) {
                $completeUrl .= $param . (($value != Null) ? "=$value&" : '&');
            }

            $completeUrl = rtrim($completeUrl, "&");
        }
        return $completeUrl;
    }

    /**
     * Returns Array of headers and their values
     * 
     * @since 1.0.0
     * 
     * @return string 
     */
    private function getRequestHeaders() {

        $headers = array();

        foreach ($this->urlHeaders as $header => $value) {
            $headers[] = "$header:$value";
        }

        return $headers;
    }

    /**
     * Launch request to url with parameters and headers
     * 
     * @since 1.0.0
     * 
     * @return string   request output
     */
    public function launchRequest() {

        $fullUrl    = $this->getCompleteUrl();
        $headers    = $this->getRequestHeaders();

        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $fullUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        if (count($headers) != 0) {
            curl_setopt($ch, CURLOPT_HEADER, $headers);
        }

        $output = curl_exec($ch);

        curl_close($ch);

        return $output;
    }
}

?>