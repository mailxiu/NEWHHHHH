<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en" class="no-js" style="height: 100%;min-height: 1080px;width: 100%;min-width: 720px;">


<head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">


    <title>用户管理页面</title>
    <jsp:include page="/static/style.jsp"/>

</head>

<body class="gray-bg">
<div class="wrapper wrapper-content  animated fadeInRight">
    <div class="row">
        <div class="col-sm-12">
            <div class="ibox ">
                <div class="ibox-content">
                    <div class="row row-lg">
                        <div class="col-sm-12">
                            <!-- Example Card View -->
                            <div class="example-wrap">
                                <div class="demoTable" style="margin-left: 50px">
                                    <%--<div class="layui-inline">--%>
                                    <%--<input class="layui-input" name="" id="categoryCode" autocomplete="off"--%>
                                    <%--placeholder="字典目录编码">--%>
                                    <%--</div>--%>
                                    <%--<div class="layui-inline">--%>
                                    <%--<input class="layui-input" name="" id="categoryValue" autocomplete="off"--%>
                                    <%--placeholder="字典项值">--%>
                                    <%--</div>--%>

                                    <%--<div class="layui-input-inline">
                                        <input type="text" id="content"  placeholder="请输入帐号" autocomplete="off" class="layui-input">
                                    </div>--%>

                                    <button class="layui-btn  layui-btn-normal" data-type="start">开启直播</button>
                                   <%-- <button class="layui-btn  layui-btn-normal" data-type="pause">暂停直播</button>
                                    <button class="layui-btn  layui-btn-normal" data-type="recovery">恢复直播</button>--%>
                                    <button class="layui-btn  layui-btn-normal" data-type="end">结束直播</button>
                                    <button class="layui-btn  layui-btn-normal" onclick="restCountdown()">重置倒计时</button>

                                    <button class="layui-btn  layui-btn-normal" data-type="send">推送开奖号码</button>
                                    <button class="layui-btn  layui-btn-normal" data-type="config">直播配置</button>
                                    <div style="display: inline-block;float: right;margin-right: 50px">
                                        <label style="font-size: 18px">第</label>
                                        <label style="font-size: 35px;color: red" id="baohao">1</label>
                                        <label style="font-size: 18px">版</label>
                                        <label style="font-size: 18px">第</label>
                                        <label style="font-size: 35px;color: red" id="juhao">1</label>
                                        <label style="font-size: 18px">局</label>

                                        <label style="font-size: 18px">倒计时: </label>
                                        <label id="countdown" style="font-size: 35px;color: red"> 00 </label>
                                        <label style="font-size: 18px"> 秒</label>
                                    </div>

                                </div>

                                <div class="example">
                                    <table class="layui-hide" lay-filter="mainTable" id="table"></table>
                                </div>
                            </div>
                            <!-- End Example Card View -->
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<script src="${home}/static/js/layui.js" charset="utf-8"></script>
<script src="${home}/static/js/jquery-1.9.1.min.js" charset="utf-8"></script>
<script src="${home}/static/js/socket.io.min.js" charset="utf-8"></script>
<script>
    let parent = window.parent;
    console.dir(parent)

    let token = localStorage.getItem("jwtToken");
    let socketUrl = '${socket}'
    // 创建 Socket.IO 连接
    var socket = parent.socket2
    // 监听与服务器的连接成功事件
    socket.on("connect", function () {
        console.log('连接成功')
        // 发送登录消息给服务器
    });

    // 监听与服务器的连接失败事件
    socket.on("connect_error", function (error) {
        console.log('连接错误')
        socket.connect();
    });

    // 监听与服务器的断开连接事件
    socket.on("disconnect", function (reason) {
        console.log('连接断开')
        // 断线重连
        socket.connect();
    });
    let isStartLive = ${isStartLive};
    let isAdmin = ${isAdmin};
    $(document).ready(function () {
        //初始化表格,动态从服务器加载数据
        layui.use('table', function () {
            var table = layui.table;
            table.render({
                elem: '#table'
                , url: '${home}/lottery/list'
                , request: {
                    pageName: 'pageNumber' //页码的参数名称，默认：page
                    , limitName: 'pageSize' //每页数据量的参数名，默认：limit
                }
                , id: 'table'
                , height: 'full-100'
                , autoSort: false
                , where: {sortName: 'createDate', sortOrder: 'desc'}
                , toolbar: '#toolbarDemo'
                , defaultToolbar: ['filter']
                , cols: [[ //标题栏
                    /*{type: 'radio', fixed: 'left'},*/
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        hide: true
                        /*sort: true*/
                    }, {
                        title: '版号',
                        field: 'baohao'
                        , align: 'center'
                    }, {
                        title: '局号',
                        field: 'qihao',
                        align: 'center'
                    }, {
                        title: "开奖号码",
                        field: "lotteryNum",
                        align: 'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }


                    , {
                        title: "开奖时间",
                        field: "lotteryTime",
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    },
                    {   title: '操作',
                        fixed: 'right',
                        align:'center',
                        align:'center',
                        toolbar: '#barDemo',
                        width: 250,
                        minWidth:250
                    }
                ]]
                , parseData: function (res) { //res 即为原始返回的数据
                    return {
                        "code": 0, //解析接口状态
                        "data": res.records, //解析数据列表
                        "count": res.total,

                    };
                }, done: function (res, curr, count) {
                }
                , page: true
                , limits: [5, 10, 15, 20, 50, 100]
                , limit: 10 //每页默认显示的数量
            });

            //排序重载
            table.on('sort(mainTable)', function (obj) {
                table.reload('table', {initSort: obj, where: {sortName: obj.field, sortOrder: obj.type}});
            });
            table.on('toolbar(mainTable)', function (obj) {
                var checkStatus = table.checkStatus(obj.config.id);
                switch (obj.event) {

                }

            });

            var $ = layui.$, active = {
                reload: function () {
                    var content = $('#content');

                    table.reload('table', {
                        page: {
                            curr: 1 //重新从第 1 页开始
                        }
                        , where: {
                            username: content.val()
                        }
                    }, 'data');
                },
                start: function () {
                    layer.load();
                    socket.emit("startCountdown")
                },
                end: function () {
                    socket.emit("endCountdown")
                },
                pause:function (){
                    socket.emit("pauseCountdown")
                },
                recovery:function (){
                    socket.emit("recoveryCountdown")
                }
                ,
                config: function () {

                    layer.open({
                        id: 'showLayer',
                        type: 2,
                        title: '直播服务器',
                        shadeClose: true,
                        shade: false,
                        area: ['1100px', '500px'],
                        content: '${home}/lottery/startForm',
                        end: function (index) {

                        }
                    });

                },
                send: function () {
                    if(!isStartLive){
                        layer.msg('还没开启直播')
                        return

                    }
                    openSend()
                }
            };

            $('.demoTable .layui-btn').on('click', function () {
                var type = $(this).data('type');
                active[type] ? active[type].call(this) : '';
            });

            table.on('tool(mainTable)', function (obj) {
                console.log(obj)

                switch (obj.event) {
                    case 'edit':
                        var data = obj.data;
                        edit(data)
                        break;
                    case 'jiesuan':
                        var data = obj.data;
                        jiesuan(data);
                        break


                }

            });
        });

//监听登录状态
        socket.on("startCountdown", function (msg) {
            //console.log(msg);
            if (msg.code == 200) {
                $('#countdown').text(msg.data.seconds)
                $('#baohao').text(msg.data.lottery.getNextBaoHao)
                $('#juhao').text(msg.data.lottery.getNextQihao)
                if (msg.msg) {
                    isStartLive = true;
                    isAdmin = true;
                    layer.msg(msg.msg)
                }
                if(msg.data.seconds==0){
                    openSend()

                }
            }else {
                layer.msg(msg.msg)
            }
            layer.closeAll('loading');
        });
        socket.on("isStartCountdown", function (msg) {

            if (msg.code == 200) {
                layer.msg(msg.msg)
                if(msg.msg.indexOf('已经在')>-1){
                    isStartLive = true;
                }else {
                    isStartLive = false;
                    $('#countdown').text(0)
                }

            }
            layer.closeAll('loading');
        });

        function getFlowWater() {
            let username = $('#content').val();
            $.ajax({
                type: "POST",
                dataType: "json",
                url: "${home}/recharge/getFlowWater",
                data: {username},
                success: function (result) {
                    if (result.code == 200) {

                    }
                }
            });
        }

        function tableReload() {
            layui.use('table', function () {
                var table = layui.table;
                table.reload('table');
            })
        }
        function openSend(){
            if(!isAdmin){
                layer.msg('不是此账号开启的直播，无法进行推送开奖号码',{time: 3000});
                return
            }
            let width = $('html').width();
            let height = $('html').height();
            width = 720;
            height = 300;
            layer.open({
                id: 'showLayer',
                type: 2,
                title: '开奖推送',
                shadeClose: true,
                shade: false,
                area: [width+'px', height+'px'],
                content: '${home}/lottery/sendForm',
                end: function (index) {
                    tableReload()
                }
            });
        }

        function jiesuan(data){
            layer.confirm('<span style="font-size: 24px;color: red">您确定要重新结算本期吗</span>',{
                btn: ['确定','取消']
            },function (index){
                data.createTime = null;
                data.lotteryTime = null;
                layer.load();
                $.ajax({
                    type: "POST",
                    dataType: "json",
                    data:data,
                    url: "${home}/lottery/jiesuan" ,
                    success: function (result) {
                        layer.msg(result.msg, {time: 2000}, function () {
                            tableReload();
                            layer.closeAll('loading')
                            if (result.ok) {
                                layer.close(index);
                            }else {
                                layer.msg(result.msg)
                            }
                        });
                    },error:function (){
                        layer.closeAll('loading')
                    }
                });
            })
        }

        function edit(data){
            layer.msg('edit')
            layer.confirm('<span style="font-size: 24px;color: red">您确定要修改本期的号码？会把所有下注过本期的用户积分都会进行修改，可能会出现用户积分为负数，您确定要修改吗？</span>', {
                btn: ['确定','取消'] //按钮
            }, function(ind){
                layer.close(ind)
                let title = '当前号码是：<span style="font-size: 24px;color: red">'+data.lotteryNum+"</span> ,请输入你要修改后的号码"
                layer.prompt({title: title  },function(val, index){
                    //layer.msg('得到了'+val);
                    layer.close(index);
                    layer.confirm('你确定要把<span style="font-size: 24px;color: red"> '+data.lotteryNum+' </span>,改成<span style="font-size: 24px;color: red "> '+val+' </span>吗',
                        function (index3){
                            data.lotteryNum = val;
                            data.createTime = null;
                            data.lotteryTime = null;
                            layer.load();
                            $.ajax({
                                type: "POST",
                                dataType: "json",
                                data:data,
                                url: "${home}/lottery/edit" ,
                                success: function (result) {
                                    layer.msg(result.msg, {time: 2000}, function () {
                                        tableReload();
                                        layer.closeAll('loading')
                                        if (result.ok) {
                                            layer.close(index3);
                                        }else {
                                            layer.msg(result.msg)
                                        }
                                    });
                                },error:function (){
                                    layer.closeAll('loading')
                                }
                            });
                        },function (index2){
                            layer.close(index);
                        })
                });
            }, function(index){
                layer.close(index);
            });
        }
    });
    function restCountdown(){
        socket.emit('restCountdown')
    }

</script>
<script type="text/html" id="toolbarDemo">
    <span>开奖号码表</span>
</script>
<script type="text/html" id="barDemo">
    <button class="layui-btn layui-btn-normal" lay-event="jiesuan" >结算</button>
    <button class="layui-btn layui-btn-normal" lay-event="edit" >修改开奖结果</button>

</script>
</body>


</html>
