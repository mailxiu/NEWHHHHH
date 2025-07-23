<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en" class="no-js">

<head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">


    <title> - 表单验证 jQuery Validation</title>
    <meta name="keywords" content="">
    <meta name="description" content="">
    <jsp:include page="/static/style.jsp"/>

    <script src="${home}/static/js/layui.js" charset="utf-8"></script>
    <script src="${home}/static/js/jquery-1.9.1.min.js" charset="utf-8"></script>
    <script src="${home}/static/js/jquery.validate.min.js" charset="utf-8"></script>


</head>
<style>
    .layui-form-item .layui-input-inline{
        width: 800px !important;
    }
    .layui-form-pane .layui-form-label{
        width: 125px !important;
    }
    .layui-btn-sm {
        height: 38px !important;
        line-height: 38px;
    }
</style>
<body class="gray-bg">
<div class="wrapper wrapper-content animated fadeInRight">
    <div class="row">
        <div class="col-sm-12">
            <div class="ibox float-e-margins">
                <div class="ibox-content">
                    <fieldset class="layui-elem-field layui-field-title" style="margin-top: 50px;">
                        <legend>推流服务器配置</legend>
                    </fieldset>
                    <form class="layui-form layui-form-pane" >

                        <div class="layui-form-item">
                            <label class="layui-form-label">OBS服务器</label>
                            <div class="layui-input-inline layui-col-xs12 ">
                                <input type="text" name="obs" id="obs"   autocomplete="off" class="layui-input layui-col-xs8" value="${live.obs}" disabled>
                            </div>
                            <button type="button" class="layui-btn layui-btn-sm" onclick="copyText('${live.obs}')">复制</button>
                            <a class="layui-btn layui-btn-sm" onclick="openNew('https://cloud.tencent.com/document/product/267/97825')">示例文档</a>
                        </div>
                        <div class="layui-form-item">
                            <label class="layui-form-label">OBS推流码</label>
                            <div class="layui-input-inline layui-col-xs8">
                                <input type="text" name="obsStream" id="obsStream"   autocomplete="off" class="layui-input layui-col-xs8 " value="${live.obsStream}" disabled >
                            </div>
                            <button type="button" class="layui-btn layui-btn-sm" onclick="copyText('${live.obsStream}')">复制</button>
                        </div>
                        <div class="layui-form-item">
                            <label class="layui-form-label">rtmp服务器</label>
                            <div class="layui-input-inline layui-col-xs4 layui-col-sm7 layui-col-md8">
                                <input type="text" name="rtmp" id="rtmp"  autocomplete="off" class="layui-input" value="${live.rtmp}" disabled>
                            </div>
                            <button type="button" class="layui-btn layui-btn-sm" onclick="copyText('${live.rtmp}')">复制</button>
                        </div>
                        <div class="layui-form-item">
                            <label class="layui-form-label">webrtc服务器</label>
                            <div class="layui-input-inline layui-col-xs4 layui-col-sm7 layui-col-md8">
                                <input type="text" name="webrtc" id="webrtc"  autocomplete="off" class="layui-input" value="${live.webrtc}" disabled>
                            </div>
                            <button type="button" class="layui-btn layui-btn-sm" onclick="copyText('${live.webrtc}')">复制</button>
                            <a class="layui-btn layui-btn-sm" onclick="openNew('https://console.cloud.tencent.com/live/tools/webpush')">示例文档</a>
                        </div>
                        <div class="layui-form-item">
                            <label class="layui-form-label">WHIP服务器</label>
                            <div class="layui-input-inline layui-col-xs4 layui-col-sm7 layui-col-md8">
                                <input type="text" name="webrtc" id="whip"  autocomplete="off" class="layui-input" value="${live.whip}" disabled>
                            </div>
                            <button type="button" class="layui-btn layui-btn-sm" onclick="copyText('${live.whip}')">复制</button>
                        </div>

                    </form>
                </div>
            </div>
        </div>
    </div>

</div>
<script type="text/javascript">
    $(document).ready(function () {

    });
    function openNew(href){
        window.open(href, '_blank');
    }
    function copyText(val){

        let input = $('<input>');
        $('body').append(input);
        input.val(val).select();
        let c = document.execCommand('copy');
        if (c){
            layer.msg('复制成功')
        }
        input.remove();
    }
</script>

</body>

</html>
