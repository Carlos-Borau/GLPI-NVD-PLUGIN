function addEventListeners() {
    var selectVendor        = document.getElementById("nvd_cpe_vendor_dropdown");
    var selectProduct       = document.getElementById("nvd_cpe_product_dropdown");
    var selectVendorTerms   = document.getElementById("nvd_cpe_vendor_terms_dropdown");
    var selectProductTerms  = document.getElementById("nvd_cpe_product_terms_dropdown");
    var filterVendor        = document.getElementById("nvd_cpe_vendor_filter");
    var filterProduct       = document.getElementById("nvd_cpe_product_filter");
    var applyVendorFilter   = document.getElementById("nvd_cpe_apply_vendor_filter");
    var applyProductFilter  = document.getElementById("nvd_cpe_apply_product_filter");
    var clearVendorFilter   = document.getElementById("nvd_cpe_clear_vendor_filter");
    var clearProductFilter  = document.getElementById("nvd_cpe_clear_product_filter");

    addSugestedTermsEventListener(selectVendorTerms, filterVendor);
    addSugestedTermsEventListener(selectProductTerms, filterProduct);

    addFilterApplyEventListener(filterVendor, applyVendorFilter, selectVendor, selectProduct);
    addFilterApplyEventListener(filterProduct, applyProductFilter, selectProduct);

    addFilterClearEventListener(selectVendorTerms, filterVendor, clearVendorFilter, selectVendor, selectProduct);
    addFilterClearEventListener(selectProductTerms, filterProduct, clearProductFilter, selectProduct);

    selectVendor.addEventListener("change", function(){

        var vendor = this.value;

        var http = new XMLHttpRequest();

        http.onreadystatechange = function(){
            if(this.readyState == 4 && this.status == 200){
                var response = JSON.parse(this.responseText);

                selectProduct.innerHTML = selectProduct.firstChild.outerHTML;

                for (product of response){

                    var option = document.createElement('option');
                    option.value = product;
                    option.innerHTML = product;

                    selectProduct.appendChild(option);
                }
            }
        }

        script_url = window.location.origin + "/glpi/plugins/nvd/front/softwarecpe.form.php?vendor=" + vendor;
        http.open('GET', script_url);
        http.send();
    });
}

function addSugestedTermsEventListener(select, filter) {

    select.addEventListener("change", function(){

        var term = this.value;
        filter.value = term;
    });
}

function addFilterApplyEventListener(filter, apply, select, otherSelect=null) {

    apply.addEventListener("click", function(){

        select.value = "-DEFAULT-";

        if (otherSelect !== null) {
            otherSelect.innerHTML = otherSelect.firstChild.outerHTML;
        }

        var term = filter.value;
        var pattern = new RegExp(".*" + escapeRegExp(term) + ".*");
        
        var values = [...document.querySelectorAll(`#${select.id} option`)].slice(1);

        values.forEach(opt => {

            opt.style.display = pattern.test(opt.value) ? "block" : "none";
        });
    });
}

function addFilterClearEventListener(filterSelect, filter, clear, select, otherSelect=null) {

    clear.addEventListener("click", function(){

        filter.value = "";
        filterSelect.value = "-DEFAULT-";
        select.value = "-DEFAULT-";

        if (otherSelect !== null) {
            otherSelect.innerHTML = otherSelect.firstChild.outerHTML;
        }
        
        var values = [...document.querySelectorAll(`#${select.id} option`)].slice(1);

        values.forEach(opt => {

            opt.style.display = "block";
        });
    });
}

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function changeSelectedValue(select, value) {
    select.value = value;
}