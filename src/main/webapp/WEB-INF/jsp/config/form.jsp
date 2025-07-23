<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html  lang="en" class="no-js">

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

<body class="gray-bg">
<div class="wrapper wrapper-content animated fadeInRight">
    <div class="row">
        <div class="col-sm-12">
            <div class="ibox float-e-margins">
                <div class="ibox-content">
                    <form class="layui-form-pane m-t" id="frm" method="post"  style="margin-top: 20px"  >
                        <input type="hidden" id="id" name="id" value="${config.id}">

                        <div class="form-group">
                            <label class="layui-form-label control-label label-required-next">键：</label>
                            <div class="layui-input-inline">
                                <input id="skeys" name="skeys" class="form-control"  value="${config.skeys}">
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="layui-form-label control-label label-required-next">值：</label>
                            <div class="layui-input-inline">
                                <input id="kvalue" name="kvalue" class="form-control"  value="${config.kvalue}">
                            </div>
                        </div>


                        <div class="form-group">
                            <div style="margin: 0 auto !important;width: 190px">
                                <button class="btn layui-btn layui-btn-lg  layui-btn-normal" type="submit">提交</button>
                                <button class="btn layui-btn layui-btn-lg  layui-btn" type="button" onclick="closeW()">关闭</button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

</div>
<script type="text/javascript">
    $(document).ready(function () {
        $("#frm").validate({
            rules: {
                tKey: {
                    required: true,
                    minlength: 1,
                    maxlength: 20
                },
                tValue: {
                    required: true,
                    minlength: 1,
                    maxlength: 20
                }
            },
            messages: {
                tKey:{
                    required:"键不能为空",
                    minlength:'最小长度为1',
                    maxlength:'最大长度为20',
                },
                tValue:{
                    required:"值不能为空",
                    minlength:'最小长度为1',
                    maxlength:'最大长度为20',
                }
            },
            submitHandler: function (form) {
                $.ajax({
                    type: "POST",
                    dataType: "json",
                    url: "${home}/config/edit",
                    data: $(form).serialize(),
                    success: function (result) {
                        layer.msg(result.msg, {time: 2000}, function () {
                            var index = parent.layer.getFrameIndex(window.name); //先得到当前iframe层的索引
                            if (result.code==200) {
                                parent.layer.close(index);
                            }/*else {
                                parent.layer.msg(result.msg);
                            }*/
                        });
                    }
                });
            }
        });
    });
    function closeW(){
        var index = parent.layer.getFrameIndex(window.name); //先得到当前iframe层的索
        parent.layer.close(index);
    }
</script>

</body>
<style>
    .layui-form-label{width: 130px !important;}
    .layui-form-item{margin-bottom: 10px !important;}
    .row{ margin: 0 !important;}
</style>
</html>
