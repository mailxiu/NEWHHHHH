<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en" class="no-js" style="overflow: hidden;height: 100%;min-height: 1080px;min-width: 720px;width: 100%">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
    <title>直播游戏管理端</title>

    <jsp:include page="/static/style.jsp"/>
    <%--<link rel="stylesheet" href="${home}/static/css/xadmin.css"  media="all">--%>
</head>
<body>
<div class="layui-layout layui-layout-admin">
    <div class="layui-header">

        <div id="scrollText">


        </div>
        <div style="width: 50%;margin: 0 auto">
            <div class="marquee">

                <span id="online"></span>
            </div>
        </div>

        <div class="layui-logo" style="color: white!important;" id="sideMenuId">直播游戏管理端</div>
        <!-- 头部区域（可配合layui 已有的水平导航） -->
        <ul class="layui-nav layui-layout-left ">
            <li class="layui-nav-item layui-show-xs-inline-block " lay-header-event="menuLeft">
                <i class="layui-icon layui-icon-spread-left"></i>
            </li>
            <c:choose>
            <c:when test="${isAdmin == 1}">
                <li class="layui-nav-item ">
                    <a onclick=" xadmin.add_tab('首页','${home}'+'/index/index')"
                       style="color: white !important; background-color: #4f93fe !important;">首页</a>
                </li>
                <li class="layui-nav-item ">
                    <a onclick=" xadmin.add_tab('开奖管理','${home}'+'/lottery/index')"
                       style="color: white !important; background-color: #4f93fe !important;">开奖管理</a>
                </li><li class="layui-nav-item ">
                <a onclick=" xadmin.add_tab('用户列表','${home}'+'/sysUser/index')"
                   style="color: white !important; background-color: #4f93fe !important;">用户注册及上下分</a>
            </li>
            </c:when>
            <c:otherwise >
                <c:if test="${isLive == 1}">
                    <li class="layui-nav-item ">
                        <a onclick=" xadmin.add_tab('开奖管理','${home}'+'/lottery/index')"
                           style="color: white !important; background-color: #4f93fe !important;">开奖管理</a>
                    </li>
                </c:if>
            </c:otherwise>
            </c:choose>
        </ul>
        <ul class="layui-nav layui-layout-right">
            <li class="layui-nav-item layui-hide layui-show-md-inline-block">
                <a href="javascript:;"
                   style="background-color:#4f93fe!important;color: white !important; line-height: 57px !important;">
                    ${nickName}
                </a>
                <dl class="layui-nav-child" style="top: 55px !important;">

                    <dd ><a href="${home}/loginout" style="font-size: 18px !important;line-height: 40px !important;height: 40px !important; color: #4f93fe !important;text-align: center !important;">退出</a></dd>
                </dl>
            </li>
            <li class="layui-nav-item layui-hide layui-show-md-inline-block">
                <c:choose>
                <c:when test="${isAdmin == 1 && isLive!=1} ">
                    <a onclick="xadmin.add_tab('用户列表','${home}'+'/sysUser/index?status=1')"
                       style="background-color:#4f93fe!important;color: white !important;" title="点击跳转在线人数">
                        在线人数：
                        <span id="online1" style="font-size: 24px ;color:red;">0</span> 人
                    </a>

                </c:when>
                <c:otherwise>
                    <a style="background-color:#4f93fe!important;color: white !important;" title="点击跳转在线人数">
                        在线人数：
                        <span id="online1" style="font-size: 24px ;color:red;">0</span> 人

                    </a>
                </c:otherwise>
                </c:choose>

            </li>
            <li class="layui-nav-item layui-hide layui-show-md-inline-block"
                style="background-color:#4f93fe!important;color: white !important;cursor: pointer ">
                <i class="layui-icon" onclick="refresh()" style="font-size: 20px" title="刷新在线状态">&#xe666;</i>
            </li>
            <%--<li class="layui-nav-item" lay-header-event="menuRight" lay-unselect>
                <a href="javascript:;">
                    <i class="layui-icon layui-icon-more-vertical"></i>
                </a>
            </li>--%>
        </ul>
    </div>

    <div class="layui-side " id="sideMenu">
        <div class="layui-side-scroll">
            <!-- 左侧导航区域（可配合layui已有的垂直导航） -->
            <ul class="layui-nav layui-nav-tree" lay-filter="test">
                <c:choose>
                <c:when test="${isAdmin==1}">
                    <li class="layui-nav-item ">
                        <a href="javascript:;">直播管理</a>
                        <dl class="layui-nav-child">
                            <dd><a onclick="xadmin.add_tab('开奖管理','${home}'+'/lottery/index')">开奖管理</a></dd>
                        </dl>
                        <dl class="layui-nav-child">
                            <dd><a onclick="xadmin.add_tab('限注列表','${home}'+'/limitMoney/index')">限注列表</a></dd>
                        </dl>
                        <dl class="layui-nav-child">
                            <dd><a onclick="xadmin.add_tab('直播参数配置','${home}'+'/config/index')">直播参数</a></dd>
                        </dl>
                    </li>
                    <li class="layui-nav-item ">
                        <a href="javascript:;">用户管理</a>
                        <dl class="layui-nav-child">
                            <dd><a onclick="xadmin.add_tab('用户列表','${home}'+'/sysUser/index')">用户列表</a></dd>
                        </dl>

                        <dl class="layui-nav-child">
                            <dd><a onclick="xadmin.add_tab('上下分列表','${home}'+'/recharge/index')">上下分列表</a></dd>
                        </dl>
                        <dl class="layui-nav-child">
                            <dd><a onclick="xadmin.add_tab('用户投注列表','${home}'+'/userLottery/index')">用户投注列表</a>
                            </dd>
                        </dl>
                        <dl class="layui-nav-child">
                            <dd><a onclick="xadmin.add_tab('下注号码统计列表','${home}'+'/userLottery/count')">下注号码统计列表</a>
                            </dd>
                        </dl>
                        <dl class="layui-nav-child">
                            <dd><a onclick="xadmin.add_tab('用户活跃列表','${home}'+'/activeUser/index')">用户活跃列表</a>
                            </dd>
                        </dl>
                        <dl class="layui-nav-child">
                            <dd><a onclick="xadmin.add_tab('暖场账号配置列表','${home}'+'/exclude/index')">暖场账号配置列表</a>
                            </dd>
                        </dl>
                    </li>
                </c:when>
                <c:otherwise>
                    <c:if test="${isLive==1}">
                        <li class="layui-nav-item ">
                            <a href="javascript:;">直播管理</a>
                            <dl class="layui-nav-child">
                                <dd><a onclick="xadmin.add_tab('开奖管理','${home}'+'/lottery/index')">开奖管理</a></dd>
                            </dl>
                            <dl class="layui-nav-child">
                                <dd><a onclick="xadmin.add_tab('限注列表','${home}'+'/limitMoney/index')">限注列表</a></dd>
                            </dl>
                            <dl class="layui-nav-child">
                                <dd><a onclick="xadmin.add_tab('直播参数配置','${home}'+'/config/index')">直播参数</a></dd>
                            </dl>
                        </li>
                    </c:if>
                </c:otherwise>

                </c:choose>

            </ul>
        </div>
    </div>

    <div class="layui-body" style="min-width: 720px">
        <div class="layui-tab" lay-filter="xbs_tab" lay-allowclose="false">
            <ul class="layui-tab-title">
            </ul>
            <div class="layui-tab-content">

            </div>
        </div>

        <!-- 内容主体区域 -->
        <%--        <div style="padding: 15px;">内容主体区域。记得修改 layui.css 和 js 的路径</div>--%>
    </div>
    <%--
        <div class="layui-footer">
            <!-- 底部固定区域 -->
            底部固定区域
        </div>--%>
</div>
<script src="${home}/static/js/jquery-1.9.1.min.js" charset="utf-8"></script>
<script src="${home}/static/js/layui.js" charset="utf-8"></script>
<script src="${home}/static/js/xadmin.js" charset="utf-8"></script>
<script src="${home}/static/js/socket.io.min.js" charset="utf-8"></script>
<script src="${home}/static/js/jquery.marquee.min.js" charset="utf-8"></script>
<script>
    //JS
    layui.use(['element', 'layer', 'util'], function () {
        var element = layui.element
            , layer = layui.layer
            , util = layui.util
            , $ = layui.$;

        //头部事件
        util.event('lay-header-event', {
            //左侧菜单事件
            menuLeft: function (othis) {
                $('#sideMenuId').toggleClass('layui-hide-xs');
                $('#sideMenu').toggleClass('layui-hide-xs');

                if ($('#sideMenu').hasClass('layui-hide-xs')) {
                    $('.layui-layout-left').css('left', 0 + 'px');
                    $('.layui-body').css('left', 0 + 'px');
                    $('.layui-footer').css('left', 0 + 'px');
                    $('#sideMenuId').css('display', 'none')
                    $('#sideMenu').css('display', 'none')
                } else {
                    $('.layui-layout-left').css('left', 200 + 'px');
                    $('.layui-body').css('left', 200 + 'px');
                    $('.layui-footer').css('left', 200 + 'px');
                    $('#sideMenuId').css('display', 'block')
                    $('#sideMenu').css('display', 'block')
                }

            }
            , menuRight: function () {
                layer.open({
                    type: 1
                    , content: '<div style="padding: 15px;">处理右侧面板的操作</div>'
                    , area: ['260px', '100%']
                    , offset: 'rt' //右上角
                    , anim: 5
                    , shadeClose: true
                });
            }
        });
        let isAdmin = ${isAdmin}
        let isLive = ${isLive};
        if(isAdmin){
            xadmin.add_tab('首页', '${home}' + '/index/index');
            xadmin.add_tab('开奖管理', '${home}' + '/lottery/index');
            xadmin.add_tab('首页', '${home}' + '/index/index');
        }else  {
            xadmin.add_tab('开奖管理', '${home}' + '/lottery/index')
        }

    });

    function addTab() {
        layui.use(['element', 'layer', 'util'], function () {
            var element = layui.element
                , layer = layui.layer
                , util = layui.util
                , $ = layui.$;
            element.tabAdd('xbs_tab', {
                title: '用户列表'//用于演示
                , content: '内容' + (Math.random() * 1000 | 0)
                , id: new Date().getTime() //实际使用一般是规定好的id，这里以时间戳模拟下
            })

        });
    }

    let token = localStorage.getItem("jwtToken");
    let socketUrl = '${socket}'
    // 创建 Socket.IO 连接
    var socket2 = io(socketUrl, {
        query: {
            online: token,
            token:token,
            transport: 'websocket'
        },
    });
    // 监听与服务器的连接成功事件
    socket2.on("connect", function () {

        console.log('连接成功')
        // 发送登录消息给服务器
    });

    // 监听与服务器的连接失败事件
    socket2.on("connect_error", function (error) {
        console.log('连接错误')
        socket2.connect();
    });

    // 监听与服务器的断开连接事件
    socket2.on("disconnect", function (reason) {
        console.log('连接断开')
        // 断线重连
        socket2.connect();
    });
    socket2.on('online', function (result) {
        //$('#online').text(result)
        $('#online1').text(result)
    })
    socket2.on('notice', function (result) {
        // $('#online').text(result)
        //$('#online1').text(result)

        if (result.code == 200) {
            let data = result.data;
            let nextBaoHao = data.banhao.getNextBaoHao;
            let nextQihao = data.banhao.getNextQihao;
            let betting = data.betting;
            let total_amount = 0;
            let msg = []
            for (let i in betting) {
                let bettingElement = betting[i];
                total_amount = total_amount * 1 + bettingElement.total_amount * 1;
                msg.push(bettingElement.lottery_number + ':' + bettingElement.total_amount)
            }
            let html = "第" + nextBaoHao + '版第' + nextQihao + '局已下注：' + total_amount;
            if (msg.length > 0) {
                html += '  ,下注详情,' + msg.join(',')
            }

            $('#online').text(html)
        } else {
            $('#online').text(result.msg)
        }
    })
    window.socket2 = socket2;


    var $scrollText = $('#scrollText');
    var scrollWidth = $scrollText[0].scrollWidth;
    var scrolling = function () {
        $scrollText.animate({
            scrollLeft: scrollWidth
        }, 5000, 'linear', function () {
            var $clone = $scrollText.clone();
            $scrollText.parent().append($clone.prop('style', ''));
            $scrollText.remove();
            $scrollText = $clone;
            scrolling();
        });
    };
    //scrolling();
    $('.marquee').marquee({
        duration: 10000,
        gap: 50,
        delayBeforeStart: 0,
        direction: 'left',
        loop: -1
    });

    function refresh() {
        socket2.emit('refresh');
        layer.msg('在线人数刷新成功')
    }


</script>
<style>
    .marquee {
        width: 100%;
        white-space: nowrap;
        overflow: hidden;
        color: white;
        margin-top: 20px;
        font-size: 18px;
    }

    #scrollText {
        white-space: nowrap;
        overflow: hidden;
        position: relative;
        color: white;
        margin-top: 20px;
        font-size: 18px;
        margin-left: 50%;
        width: 100px;
        display: none;
    }

    .layui-nav .layui-nav-item {
        line-height: 55px !important;
    }

    .dl {
        margin-bottom: 0 !important;
    }
</style>
</body>
</html>
