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
                    <form class="layui-form-pane m-t" id="frm" method="post"    style="margin-top: 20px">
                        <input type="hidden" id="id" name="id" value="${user.id}">

                        <div class="layui-form-item">
                            <div class="layui-inline">
                            <label class="layui-form-label label-required-next">用户账号：</label>
                            <div class="layui-input-inline">
                                <input id="username" name="username" class="layui-input" type="text" value="${user.username}">
                            </div>
                        </div>
                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                            <label class="layui-form-label label-required-next">用户昵称：</label>
                            <div class="layui-input-inline">
                                <input id="nickName" name="nickName" class="layui-input" type="text" value="${user.nickName}">
                            </div>
                        </div>
                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                            <label class="layui-form-label label-required-next">用户密码：</label>
                            <div class="layui-input-inline">
                                <input id="password" name="password" class="layui-input" type="text" value="${user.password}">
                            </div>
                        </div>
                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                            <label class="layui-form-label control-label ">用户积分：</label>
                            <div class="layui-input-inline">
                                <input id="money" name="money" class="layui-input" type="text" value="${user.money}" disabled="disabled">
                            </div>
                            </div>
                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                            <label class="layui-form-label control-label">是否管理员：</label>
                            <div class="layui-input-inline">
                                <select name="isAdmin" class="form-control">
                                    <option value="1" ${user.isAdmin == 1 ?'selected="selected"':''} >是</option>
                                    <option value="0" ${user.isAdmin == null || user.isAdmin == 0 ?'selected="selected"':''}>不是</option>
                                </select>
                            </div>
                            </div>
                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                            <label class="layui-form-label control-label">是直播员：</label>
                            <div class="layui-input-inline">
                                <select name="isLive" class="form-control">
                                    <option value="1" ${user.isLive == 1 ?'selected="selected"':''} >是</option>
                                    <option value="0" ${user.isLive == null || user.isLive == 0 ?'selected="selected"':''}>不是</option>
                                </select>
                            </div>
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
                username: {
                    required: true,
                    minlength: 1,
                    maxlength: 20
                },
                nickName: {
                    required: true,
                    minlength: 2,
                    maxlength: 20
                },
                password: {
                    minlength: 4,
                    maxlength: 40,
                    required: true,
                },
            },
            messages: {
                username:{
                    required:"用户名必填",
                    minlength:'最小长度为1',
                    maxlength:'最大长度为20',
                },
                nickName:{
                    required:"用户昵称必填",
                    minlength:'最小长度为2',
                    maxlength:'最大长度为20',
                },
                password:{
                    required:"密码必填",
                    minlength:'最小长度为4',
                    maxlength:'最大长度为40',
                }
            },
            submitHandler: function (form) {
                $.ajax({
                    type: "POST",
                    dataType: "json",
                    url: "${home}/sysUser/add",
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
