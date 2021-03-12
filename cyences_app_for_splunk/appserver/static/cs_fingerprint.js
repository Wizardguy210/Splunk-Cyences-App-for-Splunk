require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!'
], function ($, mvc) {

    'use strict';
    let submittedTokens = mvc.Components.getInstance('submitted');

    function startLoadingOnCell($cell){
        let loadingImageURL = '/static/app/cyences_app_for_splunk/loading_image.gif';
        let loadingImageHeight = 20;
        let loadingImageWidth = 20;
        $cell.append('<img src="' + loadingImageURL + '" alt="" border="0" height="' + loadingImageHeight + '" width="' + loadingImageWidth + '" style="float:right;">');
    }

    function stopLoadingOnCell($cell){
        $cell.children('img').remove();
    }

    function doLansweeperScan(ip){
        // TODO - below block of code is just for reference, need to update with the current use-case
        $cell = $("#loading_div");
        console.log('Lansweeper Scan for ip: ' + ip);
        startLoadingOnCell($cell);

        let service = mvc.createService();
        let data = {
            "ip": ip
        };
        data = JSON.stringify(data);
        service.get("/LansweeperScan", {"data": data}, function(error, response){
            stopLoadingOnCell($cell);
            response = response.data.entry[0].content;
            if(response && response['scan_result'] && response['scan_result'] != ''){
                // TODO - Write scan result to #lansweeper_fingerprint_info div
                console.log(response['scan_result']);
            }
            else if(response && response['error'] && response['error'] != ''){
                // TODO - Write scan result to #lansweeper_fingerprint_info div
                console.error(response['error']);
            }
            else{
                console.error("Lansweeper Scan: Unknown error in performing action.");
            }
        });
    }

    $("#btn_lansweeper_scan").on("click", function(){
        let ip = submittedTokens.get("tkn_ip");
        let scanResults = doLansweeperScan(ip);
        // TODO - Write scan result to #lansweeper_fingerprint_info div
    });

});
