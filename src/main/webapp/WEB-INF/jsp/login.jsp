<%--
  Created by IntelliJ IDEA.
  User: 90566
  Date: 2022/7/19
  Time: 10:24
  To change this template use File | Settings | File Templates.
--%>
<%
    request.setAttribute("home", request.getContextPath());
%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>


<html  lang="en" class="no-js">
<head>
    <title>登录</title>
    <link rel="stylesheet" href="${home}/static/css/layui.css" media="all">

    <script src="${home}/static/js/layui.js" charset="utf-8"></script>
    <script src="${home}/static/js/jquery-1.9.1.min.js" charset="utf-8"></script>
    <script src="${home}/static/js/base64js.min.js" charset="utf-8"></script>
</head>
<body style="background-image: url('${home}/static/images/back.png'); height: 100%;width: 100%;background-size: 100%;overflow: hidden;display: flex;align-items: center;justify-content: center">
<div style="display: flex;flex-direction: row;
        height: 350px;width:900px;margin: 0 auto;padding: 0 auto;">
    <div style="flex: 1;position: relative;height: 100%">
        <img src="${home}/static/images/login2.png" style="width: 100%;height: 100%">
        <label style="position: absolute;top: 4%;display: block;margin-left: 4%; color: #337ff1;font-size: 24px">游戏直播管理平台</label>
    </div>
    <div style="flex: 3;background: white;border-radius: 5px;height: 100%">
        <div style="margin: 0 auto;width: 100%;margin-top: 5%">
            <label style="display: block;margin: 0 auto;width: 250px; font-size: 30px;font-weight: bold">欢迎登录后台系统</label>

        </div>
        <div style="margin: 0 auto;width: 100%;margin-top: 25px;">
        <form class="layui-form" style="margin: 0 auto;width: 330px" method="post" >
            <div class="layui-form-item">
                <label class="layui-form-label">用户账号</label>
                <div class="layui-input-inline">
                    <input type="text" name="username" lay-verify="required" lay-reqtext="请填写用户名" placeholder="请输入" autocomplete="off" class="layui-input">
                </div>
            </div>
            <div class="layui-form-item">
                <label class="layui-form-label">用户密码</label>
                <div class="layui-input-inline">
                    <input type="password" name="password"  placeholder="请输入密码"lay-verify="required" lay-reqtext="请填写密码" autocomplete="off" class="layui-input">
                </div>

               <%-- <div class="layui-form-mid layui-word-aux">请填写6到12位密码</div>--%>
            </div>
            <div class="layui-form-item">
                <label class="layui-form-label">验证码</label>
                <div class="layui-input-inline">
                    <input type="text"  name="text" lay-verify="required" lay-reqtext="请输入验证码"  class="layui-input" style="display: inline-block;width: 50%">
                    <img alt="验证码" id="captcha" src='VerifyCodeServlet' title="看不清？点击刷新"
                         onclick="refreshCheckCode()"
                         style="display: inline-block;height: 50px;width: 40%"/>
                </div>
            </div>
            <div class="layui-form-item">
                <div class="layui-input-block">
                    <button type="button" id="sub" class="layui-btn layui-btn-lg" style="background: #337ff1" lay-submit="" lay-filter="demo1">立即登录</button>

                </div>
            </div>
        </form>
        </div>
    </div>
</div>
<script>
    function refreshCheckCode() {
        $('#captcha').attr('src','VerifyCodeServlet?time=' + new Date().getTime())
    }
    layui.use(['form'], function(){
        var form = layui.form;



        //自定义验证规则
    /*    form.verify({
            title: function(value){
                if(value.length < 5){
                    return '标题至少得5个字符啊';
                }
            }
            ,pass: [
                /^[\S]{6,12}$/
                ,'密码必须6到12位，且不能出现空格'
            ]
            ,content: function(value){
                layedit.sync(editIndex);
            }
        });*/


        //监听提交
        form.on('submit(demo1)', function(data){
            //document.createElement("script")
            let base64 = new Base64();
            let field = data.field;
            let pass = base64.encode(field.password);
            field.password = pass+"${str}";
            let user = base64.encode(field.username);
            field.username = user+'${str}';

           /* layer.alert(JSON.stringify(data.field), {
                title: '最终的提交信息'
            })*/
            $.ajax({
                type: "POST",
                dataType: "json",
                data:data.field,
                url: "${home}/user/login",
                success: function (result) {
                    layer.msg(result.msg, {time: 2000}, function () {
                        if(result.code==200){
                            localStorage.setItem('jwtToken', result.data.token);
                            location.href = "index"
                        }
                    });
                }
            });
            return false;
        });


    });
</script>
</body>
</html>
