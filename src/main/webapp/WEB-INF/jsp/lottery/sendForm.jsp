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
   /* .layui-form-item .layui-input-inline{
        width: 800px !important;
    }*/
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
                        <legend>第${lottery.getNextBaoHao}版第${lottery.getNextQihao}局开奖</legend>
                    </fieldset>
                    <form class="layui-form layui-form-pane" >

                        <div class="layui-form-item">
                            <label class="layui-form-label">开奖号码</label>
                            <div class="layui-input-inline layui-col-xs8 " style="width: 135px">
                                <input type="number" name="lotteryNum" id="lotteryNum"  placeholder="请输入开奖号码"  autocomplete="on" class="layui-input layui-col-xs6" value="${lottery.lotteryNum}" >

                            </div>
                            <button type="button" class="layui-btn layui-btn  layui-btn-normal" onclick="pushAndnext()">推送并开始下局<span id="seconds" style="font-size: 20px"></span></button>
                            <button type="button" class="layui-btn layui-btn " onclick="pushAndStop()">推送并暂停直播<span id="seconds2" style="font-size: 20px"></span></button>
                        </div>


                    </form>
                </div>
            </div>
        </div>
    </div>

</div>
<script type="text/javascript">
    $(document).ready(function () {
        $('#lotteryNum').focus();

    });
    let seconds = '${seconds}'
    function pushAndnext(){
        if(seconds>0){
            layer.msg('还没到开奖时间')
            return;
        }
        let lotteryNum = $('#lotteryNum').val();
        if(!lotteryNum){
            layer.msg('开奖号码为空')
            return
        }
        if(lotteryNum>24){
            layer.msg('开奖号码不能大于24',function (){})
            return;
        }
        let lottery = {}
        lottery.lotteryNum = lotteryNum;
        let baoHao = '${lottery.getNextBaoHao}';
        let qiHao = '${lottery.getNextQihao}'
        lottery.baohao = baoHao;
        lottery.qihao = qiHao;
        let msg = '您确定开奖号码是 【<span style="font-size: 24px;color:#4f93fe " >第'+baoHao+'第'+qiHao+'局</span> 】开奖号码是： <span style="color: #c00000;font-size: 24px;">'+lotteryNum+'</span> 吗？？并开始下一局';
        let isSend = false;
        layer.confirm(msg, {
            title:'开奖并开始下局',
            btn: ['确定', '取消'] //按钮
        }, function () {
            if(!isSend){
                isSend = true;
                $.ajax({
                    type: "POST",
                    dataType: "json",
                    url: "${home}/lottery/pushAndNext",
                    data: lottery,
                    success: function (result) {
                        layer.msg(result.msg, {time: 2000}, function () {
                            var index = parent.layer.getFrameIndex(window.name); //先得到当前iframe层的索引
                            if (result.code==200) {
                                parent.layer.close(index);
                            }else {
                                layer.msg(result.msg)
                            }
                        });
                    }
                });
            }else {
                layer.msg('已推送，请勿重复推送')
            }

        }, function () {

        })
    }
    function pushAndStop(){
        if(seconds>0){
            layer.msg('还没到开奖时间')
            return;
        }
        let lotteryNum = $('#lotteryNum').val();
        if(!lotteryNum){
            layer.msg('开奖号码为空')
            return
        }
        let lottery = {}
        lottery.lotteryNum = lotteryNum;
        let baoHao = '${lottery.getNextBaoHao}';
        let qiHao = '${lottery.getNextQihao}'
        lottery.baohao = baoHao;
        lottery.qihao = qiHao;
        let msg = '您确定开奖号码是 【<span style="font-size: 24px;color:#4f93fe " >第'+baoHao+'第'+qiHao+'局</span> 】开奖号码是： <span style="color: #c00000;font-size: 24px;">'+lotteryNum+'</span> 吗？？并暂停直播';
        let isSend = false;
        layer.confirm(msg, {
            title:'开奖并开始下局',
            btn: ['确定', '取消'] //按钮
        }, function () {
            if(!isSend){
                $.ajax({
                    type: "POST",
                    dataType: "json",
                    url: "${home}/lottery/pushAndStop",
                    data: lottery,
                    success: function (result) {
                        layer.msg(result.msg, {time: 2000}, function () {
                            var index = parent.layer.getFrameIndex(window.name); //先得到当前iframe层的索引
                            if (result.code==200) {
                                parent.layer.close(index);
                            }else {
                                layer.msg(result.msg)
                            }
                        });
                    }
                });
            }else {
                layer.msg('已推送，请勿重复推送')
            }

        }, function () {

        })
    }

    let timer = setInterval(function() {
        if(seconds>=0){
            $("#seconds").text('('+seconds+')');
            $("#seconds2").text('('+seconds+')');
            seconds--;
        }else {
            $("#seconds").text('')
            $("#seconds2").text('')
            clearInterval(timer)
            timer = null;
        }

    }, 1000);
</script>

</body>
<style>
    .row{margin: 0 !important;}
</style>
</html>
