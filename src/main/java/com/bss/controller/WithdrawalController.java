/*     */ package com.bss.controller;
/*     */ 
/*     */ import com.alibaba.fastjson.JSON;
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.alipay.api.AlipayApiException;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.core.metadata.IPage;
/*     */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
/*     */ import com.bss.enmus.WithdrawalEnum;
/*     */ import com.bss.entity.Configure;
/*     */ import com.bss.entity.Member;
/*     */ import com.bss.entity.User;
/*     */ import com.bss.entity.Withdrawal;
/*     */ import com.bss.service.MemberService;
/*     */ import com.bss.service.WithdrawalService;
/*     */ import com.bss.service.impl.AlipayServiceImpl;
/*     */ import com.bss.service.impl.ConfigureServiceImpl;
/*     */
/*     */ import java.io.Serializable;
/*     */ import java.text.DateFormat;
/*     */ import java.text.SimpleDateFormat;
/*     */ import java.util.Calendar;
/*     */ import java.util.List;
/*     */ import java.util.Map;
/*     */ import java.util.Random;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.http.HttpSession;
/*     */ import org.springframework.web.bind.annotation.DeleteMapping;
/*     */ import org.springframework.web.bind.annotation.GetMapping;
/*     */ import org.springframework.web.bind.annotation.PathVariable;
/*     */ import org.springframework.web.bind.annotation.PostMapping;
/*     */ import org.springframework.web.bind.annotation.PutMapping;
/*     */ import org.springframework.web.bind.annotation.RequestBody;
/*     */ import org.springframework.web.bind.annotation.RequestMapping;
/*     */ import org.springframework.web.bind.annotation.RequestParam;
/*     */ import org.springframework.web.bind.annotation.RestController;
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ @RestController
/*     */ @RequestMapping({"withdrawal"})
/*     */ public class WithdrawalController
/*     */   extends ApiController
/*     */ {
/*     */   @Resource
/*     */   private WithdrawalService withdrawalService;
/*     */   @Resource
/*     */   private MemberService memberService;
/*     */   @Resource
/*     */   private AlipayServiceImpl alipayService;
/*     */   @Resource
/*     */   private ConfigureServiceImpl configureService;
/*     */   
/*     */   @GetMapping({"/calculate"})
/*     */   public R calculate(HttpSession session) {
/*  66 */     StringBuilder sb = new StringBuilder();
/*     */     
/*  68 */     User user = (User)session.getAttribute("user");
/*     */     
/*  70 */     String time = (String)session.getAttribute("exchange_time");
/*  71 */     String uid = (String)session.getAttribute("exchange_uid");
/*     */     
/*  73 */     QueryWrapper<Withdrawal> queryWrapper = new QueryWrapper();
/*  74 */     queryWrapper.select(new String[] { "IFNULL(sum(points),0) as points" });
/*  75 */     queryWrapper.eq("merchant", user.getMerchant());
/*     */     
/*  77 */     if (!uid.equals("")) {
/*  78 */       queryWrapper.eq("uid", uid);
/*  79 */       sb.append("用户范围：" + uid + "<br>");
/*     */     } else {
/*  81 */       sb.append("用户范围：全体用户<br>");
/*     */     } 
/*     */     
/*  84 */     if (!time.equals("")) {
/*  85 */       sb.append("时间范围：" + time + "<br>");
/*  86 */       String[] split = time.split(" - ");
/*  87 */       String startTime = split[0].trim() + " 00:00:00";
/*  88 */       String endTime = split[1].trim() + " 23:59:59";
/*  89 */       queryWrapper.between("create_time", startTime, endTime);
/*     */     } else {
/*  91 */       sb.append("时间范围：不限时间<br>");
/*     */     } 
/*     */     
/*  94 */     queryWrapper.eq("state", "已处理");
/*     */     
/*  96 */     Map<String, Object> calculate_map = this.withdrawalService.getMap((Wrapper)queryWrapper);
/*     */     
/*  98 */     sb.append("提现金额总数：" + calculate_map.get("points") + "元<br>");
/*     */     
/* 100 */     QueryWrapper<Withdrawal> real_queryWrapper = new QueryWrapper();
/* 101 */     real_queryWrapper.select(new String[] { "IFNULL(sum(real_money),0) as points" });
/* 102 */     real_queryWrapper.eq("merchant", user.getMerchant());
/*     */     
/* 104 */     if (!uid.equals("")) {
/* 105 */       real_queryWrapper.eq("uid", uid);
/*     */     }
/*     */     
/* 108 */     if (!time.equals("")) {
/* 109 */       String[] split = time.split(" - ");
/* 110 */       String startTime = split[0].trim() + " 00:00:00";
/* 111 */       String endTime = split[1].trim() + " 23:59:59";
/* 112 */       real_queryWrapper.between("create_time", startTime, endTime);
/*     */     } 
/*     */     
/* 115 */     real_queryWrapper.eq("state", "已处理");
/*     */     
/* 117 */     Map<String, Object> real_map = this.withdrawalService.getMap((Wrapper)real_queryWrapper);
/*     */     
/* 119 */     sb.append("实际到账总数：" + real_map.get("points") + "元<br>");
/*     */     
/* 121 */     return success(sb.toString());
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping
/*     */   public R selectAll(Page<Withdrawal> page, Withdrawal withdrawal) {
/* 133 */     return success(this.withdrawalService.page((IPage)page, (Wrapper)new QueryWrapper(withdrawal)));
/*     */   }
/*     */ 
/*     */   
/*     */   @GetMapping({"/list"})
/*     */   public R getList(@RequestParam(name = "pageIndex") Integer pageIndex, String uid, String month) {
/* 139 */     QueryWrapper queryWrapper = new QueryWrapper();
/*     */     
/* 141 */     queryWrapper.eq("uid", uid);
/*     */ 
/*     */ 
/*     */     
/* 145 */     queryWrapper.orderByDesc("create_time");
/*     */     
/* 147 */     Page<Withdrawal> page = (Page<Withdrawal>)this.withdrawalService.page((IPage)new Page(pageIndex.intValue(), 12L), (Wrapper)queryWrapper);
/*     */     
/* 149 */     return success(page.getRecords());
/*     */   }
/*     */ 
/*     */   
/*     */   @GetMapping({"/sum"})
/*     */   public R getSum(String uid) {
/* 155 */     QueryWrapper queryWrapper = new QueryWrapper();
/*     */     
/* 157 */     queryWrapper.select(new String[] { "IFNULL(count(*),0) as total,IFNULL(sum(points),0) as points" });
/*     */     
/* 159 */     queryWrapper.eq("uid", uid);
/*     */     
/* 161 */     Map<String, Object> map = this.withdrawalService.getMap((Wrapper)queryWrapper);
/*     */     
/* 163 */     JSONObject data = (JSONObject)JSON.toJSON(map);
/*     */     
/* 165 */     return success(data);
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"{id}"})
/*     */   public R selectOne(@PathVariable Serializable id) {
/* 176 */     return success(this.withdrawalService.getById(id));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/add"})
/*     */   public R insert(@RequestBody String jsonStr) {
/* 188 */     JSONObject o = JSONObject.parseObject(jsonStr);
/*     */     
/* 190 */     Integer uid = o.getInteger("uid");
/*     */     
/* 192 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", uid));
/*     */     
/* 194 */     if (member == null) {
/* 195 */       return success("会员信息不存在").setCode(101L).setMsg("会员信息不存在");
/*     */     }
/*     */     
/* 198 */     if (member.getState().equals("已冻结")) {
/* 199 */       return success("账号违规,联系客服清算").setCode(101L).setMsg("账号违规,已被封禁");
/*     */     }
/*     */     
/* 202 */     if (member.getPhone() == null || member.getPhone().equals("")) {
/* 203 */       return success("请绑定手机后申请提现").setCode(101L).setMsg("请绑定手机后申请提现");
/*     */     }
/*     */     
/* 206 */     List<Withdrawal> list = this.withdrawalService.list((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("uid", member.getUid())).eq("state", "待处理"));
/*     */     
/* 208 */     if (list.size() >= 1) {
/* 209 */       return success("上笔提现尚未完成").setCode(101L).setMsg("上笔提现尚未完成");
/*     */     }
/*     */ 
/*     */     
/* 213 */     if (member.getWxPay() == null || member.getWxPay().equals("")) {
/* 214 */       return success("收款码为空").setCode(101L).setMsg("收款码为空");
/*     */     }
/*     */ 
/*     */ 
/*     */     
/* 219 */     if (o.getDouble("points").doubleValue() > member.getPoints().doubleValue()) {
/*     */       
/* 221 */       member.setState("已冻结");
/*     */       
/* 223 */       this.memberService.saveOrUpdate(member);
/*     */       
/* 225 */       return success("提现积分异常").setCode(101L).setMsg("提现积分异常，账号已封禁");
/*     */     } 
/*     */ 
/*     */     
/* 229 */     Configure configure = (Configure)this.configureService.getOne((Wrapper)(new QueryWrapper()).eq("merchant", o.getString("merchant")));
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 234 */     Double charge = Double.valueOf(0.0D);
/*     */     
/* 236 */     if (configure.getPayMode().intValue() == 1) {
/* 237 */       charge = configure.getPayPoints();
/* 238 */     } else if (configure.getPayMode().intValue() == 2) {
/* 239 */       charge = Double.valueOf(o.getDouble("points").doubleValue() * configure.getPayPercent().doubleValue());
/*     */     } 
/*     */ 
/*     */     
/* 243 */     member.setPoints(Double.valueOf(member.getPoints().doubleValue() - o.getDouble("points").doubleValue()));
/*     */     
/* 245 */     this.memberService.saveOrUpdate(member);
/*     */     
/* 247 */     Calendar cal = Calendar.getInstance();
/*     */     
/* 249 */     DateFormat stateTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
/*     */     
/* 251 */     DateFormat oidTime = new SimpleDateFormat("yyyyMMddHHmmss");
/*     */     
/* 253 */     Random random = new Random();
/*     */     
/* 255 */     int i = random.nextInt(1000) + 1000;
/*     */     
/* 257 */     String oid = oidTime.format(cal.getTime()) + i;
/*     */     
/* 259 */     Withdrawal withdrawal = new Withdrawal();
/* 260 */     withdrawal.setId(Integer.valueOf(0));
/* 261 */     withdrawal.setOid(oid);
/* 262 */     withdrawal.setMerchant(o.getString("merchant"));
/* 263 */     withdrawal.setUid(o.getInteger("uid"));
/* 264 */     withdrawal.setPoints(o.getDouble("points"));
/* 265 */     withdrawal.setChargeMoney(charge);
/* 266 */     withdrawal.setRealMoney(Double.valueOf(o.getDouble("points").doubleValue() - charge.doubleValue()));
/* 267 */     withdrawal.setBalance(member.getPoints());
/* 268 */     withdrawal.setPaymentCode(o.getString("wxPay"));
/* 269 */     withdrawal.setAlipayName(member.getAlipayName());
/* 270 */     withdrawal.setAlipayAccount(member.getAlipayAccount());
/* 271 */     withdrawal.setChannel(WithdrawalEnum.AlipayAccount);
/* 272 */     withdrawal.setState("待处理");
/* 273 */     withdrawal.setCreateTime(stateTime.format(cal.getTime()));
/*     */     
/* 275 */     boolean save = this.withdrawalService.save(withdrawal);
/*     */     
/* 277 */     return success("提现成功");
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/extract"})
/*     */   public R extract(@RequestBody String jsonStr) {
/* 290 */     JSONObject o = JSONObject.parseObject(jsonStr);
/*     */     
/* 292 */     Integer uid = o.getInteger("uid");
/*     */ 
/*     */     
/* 295 */     String channel = o.getString("channel");
/*     */     
/* 297 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", uid));
/*     */     
/* 299 */     if (member == null) {
/* 300 */       return success("会员信息不存在").setCode(101L).setMsg("会员信息不存在");
/*     */     }
/*     */     
/* 303 */     if (member.getState().equals("已冻结")) {
/* 304 */       return success("账号违规,联系客服清算").setCode(101L).setMsg("账号违规,已被封禁");
/*     */     }
/*     */     
/* 307 */     if (member.getPhone() == null || member.getPhone().equals("")) {
/* 308 */       return success("请绑定手机后申请提现").setCode(101L).setMsg("请绑定手机后申请提现");
/*     */     }
/*     */     
/* 311 */     List<Withdrawal> list = this.withdrawalService.list((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("uid", member.getUid())).eq("state", "待处理"));
/*     */     
/* 313 */     if (list.size() >= 1) {
/* 314 */       return success("上笔提现尚未完成").setCode(101L).setMsg("上笔提现尚未完成");
/*     */     }
/*     */ 
/*     */ 
/*     */     
/* 319 */     if (WithdrawalEnum.AlipayAccount.getValue().equals(channel)) {
/*     */       
/* 321 */       if (member.getAlipayName() == null || member.getAlipayName().equals("")) {
/* 322 */         return success("支付宝姓名为空").setCode(101L).setMsg("支付宝姓名为空");
/*     */       }
/*     */       
/* 325 */       if (member.getAlipayAccount() == null || member.getAlipayAccount().equals("")) {
/* 326 */         return success("支付宝账号为空").setCode(101L).setMsg("支付宝账号为空");
/*     */       }
/*     */       
/* 329 */       if (member.getWxPay() == null || member.getWxPay().equals("")) {
/* 330 */         return success("收款码为空").setCode(101L).setMsg("收款码为空");
/*     */       }
/*     */     } 
/*     */ 
/*     */ 
/*     */     
/* 336 */     if (WithdrawalEnum.BankCard.getValue().equals(channel)) {
/*     */       
/* 338 */       if (member.getBankRealName() == null || member.getBankRealName().equals("")) {
/* 339 */         return success("银行卡真实姓名异常").setCode(101L).setMsg("银行卡真实姓名异常");
/*     */       }
/*     */       
/* 342 */       if (member.getBankCardNumber() == null || member.getBankCardNumber().equals("")) {
/* 343 */         return success("银行卡号错误").setCode(101L).setMsg("银行卡号错误");
/*     */       }
/*     */       
/* 346 */       if (member.getBankAccountName() == null || member.getBankAccountName().equals("")) {
/* 347 */         return success("银行卡开户行错误").setCode(101L).setMsg("银行卡开户行错误");
/*     */       }
/*     */     } 
/*     */ 
/*     */ 
/*     */     
/* 353 */     if (o.getDouble("points").doubleValue() > member.getPoints().doubleValue()) {
/*     */       
/* 355 */       member.setState("已冻结");
/*     */       
/* 357 */       this.memberService.saveOrUpdate(member);
/*     */       
/* 359 */       return success("提现积分异常").setCode(101L).setMsg("提现积分异常，账号已封禁");
/*     */     } 
/*     */     
/* 362 */     Configure configure = (Configure)this.configureService.getOne((Wrapper)(new QueryWrapper()).eq("merchant", o.getString("merchant")));
/*     */ 
/*     */ 
/*     */     
/* 366 */     int count = this.withdrawalService.count((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("uid", uid)).apply(true, "TO_DAYS(NOW())-TO_DAYS(create_time) = 0", new Object[0]));
/*     */     
/* 368 */     if (count >= configure.getWithdrawalNumber().intValue()) {
/* 369 */       return success("超过当日最大可提现次数").setCode(101L).setMsg("超过当日最大可提现次数");
/*     */     }
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 375 */     Double charge = Double.valueOf(0.0D);
/*     */     
/* 377 */     if (configure.getPayMode().intValue() == 1) {
/* 378 */       charge = configure.getPayPoints();
/* 379 */     } else if (configure.getPayMode().intValue() == 2) {
/* 380 */       charge = Double.valueOf(o.getDouble("points").doubleValue() * configure.getPayPercent().doubleValue());
/*     */     } 
/*     */ 
/*     */     
/* 384 */     member.setPoints(Double.valueOf(member.getPoints().doubleValue() - o.getDouble("points").doubleValue()));
/*     */     
/* 386 */     this.memberService.saveOrUpdate(member);
/*     */     
/* 388 */     Calendar cal = Calendar.getInstance();
/*     */     
/* 390 */     DateFormat stateTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
/*     */     
/* 392 */     DateFormat oidTime = new SimpleDateFormat("yyyyMMddHHmmss");
/*     */     
/* 394 */     Random random = new Random();
/*     */     
/* 396 */     int i = random.nextInt(1000) + 1000;
/*     */     
/* 398 */     String oid = oidTime.format(cal.getTime()) + i;
/*     */     
/* 400 */     Withdrawal withdrawal = new Withdrawal();
/* 401 */     withdrawal.setId(Integer.valueOf(0));
/* 402 */     withdrawal.setOid(oid);
/* 403 */     withdrawal.setMerchant(o.getString("merchant"));
/* 404 */     withdrawal.setUid(o.getInteger("uid"));
/* 405 */     withdrawal.setPoints(o.getDouble("points"));
/* 406 */     withdrawal.setChargeMoney(charge);
/* 407 */     withdrawal.setRealMoney(Double.valueOf(o.getDouble("points").doubleValue() - charge.doubleValue()));
/* 408 */     withdrawal.setBalance(member.getPoints());
/* 409 */     withdrawal.setPaymentCode(o.getString("wxPay"));
/* 410 */     withdrawal.setAlipayName(member.getAlipayName());
/* 411 */     withdrawal.setAlipayAccount(member.getAlipayAccount());
/* 412 */     withdrawal.setChannel(WithdrawalEnum.valueOf(channel));
/* 413 */     withdrawal.setState("待处理");
/* 414 */     withdrawal.setCreateTime(stateTime.format(cal.getTime()));
/*     */     
/* 416 */     boolean save = this.withdrawalService.save(withdrawal);
/*     */     
/* 418 */     if (save) {
/*     */ 
/*     */       
/* 421 */       if (withdrawal.getChannel().equals(WithdrawalEnum.AlipayAccount) && withdrawal.getPoints().doubleValue() <= configure.getAutomaticPayment().doubleValue()) {
/*     */         
/*     */         try {
/*     */           
/* 425 */           com.bss.utils.R transferred = this.alipayService.transfer(withdrawal.getOid());
/* 426 */           System.out.println(transferred);
/* 427 */         } catch (AlipayApiException e) {
/* 428 */           throw new RuntimeException(e);
/*     */         } 
/*     */       }
/*     */ 
/*     */       
/* 433 */       return success("提现成功");
/*     */     } 
/*     */     
/* 436 */     return failed("提现失败");
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PutMapping
/*     */   public R update(@RequestBody Withdrawal withdrawal) {
/* 450 */     return success(Boolean.valueOf(this.withdrawalService.updateById(withdrawal)));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/rebut"})
/*     */   public R rebut(String oid, String info, HttpSession session) {
/* 461 */     User user = (User)session.getAttribute("user");
/*     */     
/* 463 */     if (user == null) {
/* 464 */       return success(Boolean.valueOf(false)).setMsg("操作失败,登录失效").setCode(101L);
/*     */     }
/*     */     
/* 467 */     Withdrawal withdrawal = (Withdrawal)this.withdrawalService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("oid", oid)).eq("merchant", user.getMerchant()));
/*     */     
/* 469 */     if (withdrawal == null) {
/* 470 */       return success(Boolean.valueOf(false)).setMsg("操作失败,记录存在！").setCode(101L);
/*     */     }
/*     */     
/* 473 */     if (!withdrawal.getState().equals("待处理")) {
/* 474 */       return success(Boolean.valueOf(false)).setMsg("操作失败").setCode(101L);
/*     */     }
/*     */     
/* 477 */     withdrawal.setState("已驳回");
/*     */     
/* 479 */     withdrawal.setInfo(info);
/*     */     
/* 481 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", withdrawal.getUid()));
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 496 */     member.setPoints(Double.valueOf(member.getPoints().doubleValue() + withdrawal.getPoints().doubleValue()));
/*     */     
/* 498 */     this.memberService.saveOrUpdate(member);
/*     */     
/* 500 */     boolean update = this.withdrawalService.saveOrUpdate(withdrawal);
/*     */     
/* 502 */     JSONObject data = new JSONObject();
/*     */     
/* 504 */     data.put("state:", Boolean.valueOf(update));
/* 505 */     data.put("total:", Integer.valueOf(1));
/* 506 */     data.put("info:", info);
/*     */     
/* 508 */     return success(data).setMsg(data.toString());
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/pass"})
/*     */   public R rebut(String oid, HttpSession session) {
/* 519 */     User user = (User)session.getAttribute("user");
/*     */     
/* 521 */     if (user == null) {
/* 522 */       return success(Boolean.valueOf(false)).setMsg("操作失败,登录失效").setCode(101L);
/*     */     }
/*     */     
/* 525 */     Withdrawal withdrawal = (Withdrawal)this.withdrawalService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("oid", oid)).eq("merchant", user.getMerchant()));
/*     */     
/* 527 */     if (withdrawal == null) {
/* 528 */       return success(Boolean.valueOf(false)).setMsg("操作失败,记录存在！").setCode(101L);
/*     */     }
/*     */     
/* 531 */     if (!withdrawal.getState().equals("待处理")) {
/* 532 */       return success(Boolean.valueOf(false)).setMsg("操作失败").setCode(101L);
/*     */     }
/*     */     
/* 535 */     withdrawal.setState("已处理");
/*     */     
/* 537 */     boolean update = this.withdrawalService.saveOrUpdate(withdrawal);
/*     */     
/* 539 */     return success(Boolean.valueOf(update));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/state_all"})
/*     */   public R state_all(@RequestParam("idList") List<Long> idList, String state, String notes) {
/* 551 */     String n_state = "";
/*     */     
/* 553 */     if (state.equals("1")) {
/* 554 */       n_state = "已处理";
/*     */     } else {
/* 556 */       n_state = "已驳回";
/*     */     } 
/*     */     
/* 559 */     int success = 0;
/*     */     
/* 561 */     for (int i = 0; i < idList.size(); i++) {
/*     */       
/* 563 */       Withdrawal withdrawal = (Withdrawal)this.withdrawalService.getOne((Wrapper)(new QueryWrapper()).eq("id", idList.get(i)));
/*     */       
/* 565 */       withdrawal.setState(n_state);
/*     */       
/* 567 */       boolean b = this.withdrawalService.saveOrUpdate(withdrawal);
/*     */       
/* 569 */       if (n_state.equals("已驳回")) {
/*     */         
/* 571 */         Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", withdrawal.getUid()));
/*     */         
/* 573 */         member.setPoints(Double.valueOf(member.getPoints().doubleValue() + withdrawal.getPoints().doubleValue()));
/*     */         
/* 575 */         this.memberService.saveOrUpdate(member);
/*     */       } 
/*     */ 
/*     */       
/* 579 */       if (b) {
/* 580 */         success++;
/*     */       }
/*     */     } 
/*     */     
/* 584 */     JSONObject data = new JSONObject();
/*     */     
/* 586 */     data.put("state:", state);
/* 587 */     data.put("total:", Integer.valueOf(idList.size()));
/* 588 */     data.put("success:", Integer.valueOf(success));
/* 589 */     data.put("fail:", Integer.valueOf(idList.size() - success));
/*     */     
/* 591 */     return success(data).setMsg(data.toString());
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @DeleteMapping
/*     */   public R delete(@RequestParam("idList") List<Long> idList) {
/* 602 */     return success(Boolean.valueOf(this.withdrawalService.removeByIds(idList)));
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\WithdrawalController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */