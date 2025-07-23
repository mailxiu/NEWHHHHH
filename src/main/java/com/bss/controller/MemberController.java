/*     */ package com.bss.controller;
/*     */ 
/*     */ import com.alibaba.fastjson.JSON;
/*     */ import com.alibaba.fastjson.JSONArray;
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.core.metadata.IPage;
/*     */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
/*     */ import com.bss.enmus.SceneEnum;
/*     */ import com.bss.entity.Grade;
/*     */ import com.bss.entity.Member;
/*     */ import com.bss.entity.MemberVO2;
/*     */ import com.bss.entity.MemberVo;
/*     */ import com.bss.entity.Settlement;
/*     */ import com.bss.entity.User;
/*     */ import com.bss.service.impl.DividendServiceImpl;
/*     */ import com.bss.service.impl.GradeServiceImpl;
/*     */ import com.bss.service.impl.MemberServiceImpl;
/*     */ import com.bss.service.impl.SettlementServiceImpl;
/*     */ import java.io.Serializable;
/*     */ import java.util.List;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.http.HttpSession;
/*     */ import org.slf4j.Logger;
/*     */ import org.slf4j.LoggerFactory;
/*     */ import org.springframework.web.bind.annotation.DeleteMapping;
/*     */ import org.springframework.web.bind.annotation.GetMapping;
/*     */ import org.springframework.web.bind.annotation.ModelAttribute;
/*     */ import org.springframework.web.bind.annotation.PathVariable;
/*     */ import org.springframework.web.bind.annotation.PostMapping;
/*     */ import org.springframework.web.bind.annotation.RequestBody;
/*     */ import org.springframework.web.bind.annotation.RequestMapping;
/*     */ import org.springframework.web.bind.annotation.RequestParam;
/*     */ import org.springframework.web.bind.annotation.RestController;
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ @RestController
/*     */ @RequestMapping({"member"})
/*     */ public class MemberController
/*     */   extends ApiController
/*     */ {
/*  47 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.MemberController.class);
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private MemberServiceImpl memberService;
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private GradeServiceImpl gradeService;
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private DividendServiceImpl dividendService;
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private SettlementServiceImpl settlementService;
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping
/*     */   public R selectAll(Page<Member> page, Member member) {
/*  75 */     return success(this.memberService.page((IPage)page, (Wrapper)new QueryWrapper(member)));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/update_all"})
/*     */   public R update_all(@ModelAttribute MemberVO2 memberVO2) {
/*  87 */     Member member = (Member)this.memberService.getById(memberVO2.getId());
/*  88 */     member.setName(memberVO2.getName());
/*  89 */     member.setPortrait(memberVO2.getPortrait());
/*  90 */     member.setPoints(memberVO2.getPoints());
/*  91 */     member.setPhone(memberVO2.getPhone());
/*  92 */     member.setMid(memberVO2.getMid());
/*     */     
/*  94 */     boolean b = this.memberService.saveOrUpdate(member);
/*     */ 
/*     */     
/*  97 */     return success(member);
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
/*     */   
/*     */   @PostMapping({"/invitation"})
/*     */   public R getInvitation(@RequestParam(name = "merchant") String merchant, @RequestParam(name = "mid") Integer mid, @RequestParam(name = "partner", defaultValue = "") String partner, @RequestParam(name = "pageIndex", defaultValue = "1") Integer pageIndex) {
/* 112 */     QueryWrapper<Member> queryWrapper = new QueryWrapper();
/*     */     
/* 114 */     queryWrapper.eq("merchant", merchant);
/*     */     
/* 116 */     queryWrapper.eq("mid", mid);
/*     */     
/* 118 */     if (!partner.equals("")) {
/* 119 */       queryWrapper.eq("partner", partner);
/*     */     }
/*     */     
/* 122 */     queryWrapper.orderByDesc("create_time");
/*     */ 
/*     */     
/* 125 */     IPage<Member> iPage = this.memberService.page((IPage)new Page(pageIndex.intValue(), 15L), (Wrapper)queryWrapper);
/*     */     
/* 127 */     List<Member> memberList = iPage.getRecords();
/*     */     
/* 129 */     JSONArray arr = (JSONArray)JSON.toJSON(memberList);
/*     */     
/* 131 */     for (int i = 0; i < arr.size(); i++) {
/*     */       
/* 133 */       JSONObject t = arr.getJSONObject(i);
/*     */       
/* 135 */       Grade grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("sort", t.getInteger("partner")));
/*     */       
/* 137 */       t.put("grade_name", grade.getName());
/*     */     } 
/*     */     
/* 140 */     return success(arr);
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
/*     */   
/*     */   @PostMapping({"/invitation_v2"})
/*     */   public R getInvitation_v2(@RequestParam(name = "merchant") String merchant, @RequestParam(name = "mid") Integer mid, @RequestParam(name = "partner", defaultValue = "") String partner, @RequestParam(name = "pageIndex", defaultValue = "1") Integer pageIndex) {
/* 155 */     QueryWrapper<Member> queryWrapper = new QueryWrapper();
/*     */     
/* 157 */     queryWrapper.eq("merchant", merchant);
/*     */     
/* 159 */     queryWrapper.eq("mid", mid);
/*     */     
/* 161 */     if (!partner.equals("")) {
/* 162 */       queryWrapper.eq("partner", partner);
/*     */     }
/*     */     
/* 165 */     queryWrapper.orderByDesc("create_time");
/*     */     
/* 167 */     IPage<Member> iPage = this.memberService.page((IPage)new Page(pageIndex.intValue(), 15L), (Wrapper)queryWrapper);
/*     */     
/* 169 */     List<Member> memberList = iPage.getRecords();
/*     */     
/* 171 */     JSONArray arr = (JSONArray)JSON.toJSON(memberList);
/*     */     
/* 173 */     for (int i = 0; i < arr.size(); i++) {
/*     */       
/* 175 */       JSONObject t = arr.getJSONObject(i);
/*     */       
/* 177 */       Grade grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("sort", t.getInteger("partner")));
/*     */       
/* 179 */       t.put("grade_name", grade.getName());
/*     */     } 
/*     */     
/* 182 */     JSONObject data = new JSONObject();
/*     */     
/* 184 */     data.put("total", Long.valueOf(iPage.getTotal()));
/* 185 */     data.put("list", arr);
/*     */ 
/*     */     
/* 188 */     return success(data);
/*     */   }
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/count"})
/*     */   public R getCount(@RequestParam(name = "merchant") String merchant, @RequestParam(name = "mid", defaultValue = "") Integer mid) {
/* 195 */     int count = this.memberService.count((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("mid", mid));
/*     */     
/* 197 */     return success(Integer.valueOf(count));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"/openid"})
/*     */   public R selectOneByOpenid(String openid) {
/* 209 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("openid", openid));
/*     */     
/* 211 */     if (member == null) {
/* 212 */       return success(null).setMsg("会员不存在").setCode(1L);
/*     */     }
/*     */     
/* 215 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", member.getMerchant())).eq("sort", member.getPartner()));
/*     */     
/* 217 */     JSONObject data = (JSONObject)JSON.toJSON(member);
/*     */     
/* 219 */     data.put("grade_name", grade.getName());
/*     */     
/* 221 */     return success(data);
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"/superior"})
/*     */   public R superior(String merchant, String uid) {
/* 233 */     Member member = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("uid", uid));
/*     */     
/* 235 */     if (member == null) {
/* 236 */       return success(null).setMsg("会员不存在").setCode(1L);
/*     */     }
/*     */     
/* 239 */     Member member_t = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("uid", member.getMid()));
/*     */     
/* 241 */     if (member_t == null) {
/* 242 */       return success(null).setMsg("暂无上级").setCode(2L);
/*     */     }
/*     */     
/* 245 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", member.getMerchant())).eq("sort", member_t.getPartner()));
/*     */     
/* 247 */     JSONObject data = (JSONObject)JSON.toJSON(member_t);
/*     */     
/* 249 */     data.remove("points");
/*     */     
/* 251 */     data.remove("wxPay");
/*     */     
/* 253 */     data.remove("openid");
/*     */     
/* 255 */     data.remove("mid");
/*     */     
/* 257 */     data.remove("posterUrl");
/*     */     
/* 259 */     data.remove("state");
/*     */     
/* 261 */     data.put("grade_name", grade.getName());
/*     */ 
/*     */     
/* 264 */     return success(data);
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
/* 275 */     return success(this.memberService.getById(id));
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
/*     */   public R insert(@RequestBody MemberVo memberVo) {
/* 287 */     String name = "未设置昵称";
/*     */     
/* 289 */     Member member = new Member();
/* 290 */     member.setId(Integer.valueOf(0));
/* 291 */     member.setMerchant(memberVo.getMerchant());
/* 292 */     member.setMid(memberVo.getMid());
/* 293 */     member.setMerchant(memberVo.getMerchant());
/* 294 */     member.setUnionid(memberVo.getUnionid());
/* 295 */     member.setOpenid(memberVo.getOpenid());
/* 296 */     member.setPartner(Integer.valueOf(1));
/* 297 */     member.setName(name);
/* 298 */     member.setWxPay("");
/* 299 */     member.setScene(SceneEnum.getEnum(memberVo.getScene()));
/* 300 */     member.setPortrait("https://mmbiz.qpic.cn/mmbiz/icTdbqWNOwNRna42FI242Lcia07jQodd2FJGIYQfG0LAJGFxM4FbnQP6yfMxBgJ0F3YRqJCJ1aPAK2dQagdusBZg/0");
/* 301 */     member.setState("已激活");
/*     */     
/* 303 */     boolean save = this.memberService.save(member);
/*     */     
/* 305 */     String uid = String.valueOf(Integer.valueOf(member.getId().toString()).intValue() + 100000);
/*     */     
/* 307 */     member.setUid(uid);
/*     */     
/* 309 */     boolean update = this.memberService.saveOrUpdate(member);
/*     */     
/* 311 */     return success(member);
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/update"})
/*     */   public R update(@RequestBody String jsonStr) {
/* 323 */     System.out.println(jsonStr);
/*     */     
/* 325 */     JSONObject o = JSONObject.parseObject(jsonStr);
/*     */     
/* 327 */     String openid = o.getString("openid");
/*     */     
/* 329 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("openid", openid));
/*     */     
/* 331 */     member.setName(o.getString("name"));
/* 332 */     member.setPhone(o.getString("phone"));
/* 333 */     member.setPortrait(o.getString("portrait"));
/*     */     
/* 335 */     boolean b = this.memberService.saveOrUpdate(member);
/*     */     
/* 337 */     return success(member);
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/updateWx"})
/*     */   public R updateWx(Integer uid, String alipay_name, String alipay_account, String image) {
/* 349 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("id", uid));
/*     */     
/* 351 */     if (member != null) {
/* 352 */       member.setWxPay(image);
/* 353 */       member.setAlipayName(alipay_name);
/* 354 */       member.setAlipayAccount(alipay_account);
/* 355 */       this.memberService.saveOrUpdate(member);
/*     */     } 
/*     */     
/* 358 */     return success(member);
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/update_freeze"})
/*     */   public R update_freeze(Integer uid, String state) {
/* 370 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", uid));
/*     */     
/* 372 */     if (member != null) {
/* 373 */       member.setState(state);
/* 374 */       this.memberService.saveOrUpdate(member);
/*     */     } 
/*     */     
/* 377 */     return success(member);
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
/*     */   @PostMapping({"/update_partner"})
/*     */   public R update_partner(Integer uid, Integer partner, HttpSession session) {
/* 390 */     User user = (User)session.getAttribute("user");
/*     */     
/* 392 */     if (user == null) {
/* 393 */       return success(Boolean.valueOf(false));
/*     */     }
/*     */ 
/*     */     
/* 397 */     Member member = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("uid", uid)).eq("merchant", user.getMerchant()));
/*     */     
/* 399 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("sort", partner)).eq("merchant", user.getMerchant()));
/*     */     
/* 401 */     if (member == null) {
/* 402 */       return failed("用户不存在");
/*     */     }
/*     */     
/* 405 */     if (grade == null) {
/* 406 */       return failed("等级不存在");
/*     */     }
/*     */     
/* 409 */     R r = this.memberService.upgrade(String.valueOf(uid), partner);
/*     */     
/* 411 */     System.out.println(r);
/*     */     
/* 413 */     return r;
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
/*     */   @PostMapping({"/task_partner"})
/*     */   public R task_partner(Integer uid, Integer partner, Double bonus, HttpSession session) {
/* 427 */     User user = (User)session.getAttribute("user");
/*     */     
/* 429 */     if (user == null) {
/* 430 */       return success(Boolean.valueOf(false));
/*     */     }
/*     */ 
/*     */     
/* 434 */     Member member = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("uid", uid)).eq("merchant", user.getMerchant()));
/*     */     
/* 436 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("sort", partner)).eq("merchant", user.getMerchant()));
/*     */     
/* 438 */     if (member == null) {
/* 439 */       return failed("用户不存在");
/*     */     }
/* 441 */     if (grade == null) {
/* 442 */       return failed("等级不存在");
/*     */     }
/*     */     
/* 445 */     member.setPartner(partner);
/*     */     
/* 447 */     this.memberService.saveOrUpdate(member);
/*     */ 
/*     */     
/* 450 */     Member top_member = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("uid", member.getMid())).eq("merchant", user.getMerchant()));
/*     */     
/* 452 */     if (top_member != null)
/*     */     {
/* 454 */       if (top_member.getPartner().intValue() >= 2) {
/*     */         
/* 456 */         top_member.setPoints(Double.valueOf(top_member.getPoints().doubleValue() + bonus.doubleValue()));
/*     */         
/* 458 */         Settlement settlement = new Settlement();
/* 459 */         settlement.setId(Integer.valueOf(0));
/* 460 */         settlement.setSid(member.getUid());
/* 461 */         settlement.setUid(top_member.getUid());
/* 462 */         settlement.setType("升级分佣");
/* 463 */         settlement.setNotes("源自：下级" + member.getUid() + ",做任务升级会员");
/* 464 */         settlement.setTotal(bonus);
/*     */         
/* 466 */         this.settlementService.save(settlement);
/*     */         
/* 468 */         this.memberService.saveOrUpdate(top_member);
/*     */       } 
/*     */     }
/*     */     
/* 472 */     return success(Boolean.valueOf(true));
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
/* 483 */     return success(Boolean.valueOf(this.memberService.removeByIds(idList)));
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\MemberController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */