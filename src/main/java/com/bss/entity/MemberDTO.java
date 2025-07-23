/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.bss.enmus.SceneEnum;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/*    */
@TableName("member")
/*    */ public class MemberDTO implements Serializable {
    private static final long serialVersionUID = 1L;
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    private String merchant;
    /*    */   private String mid;
    /*    */   private String uid;
    /*    */   private String unionid;
    /*    */   private String openid;
    /*    */   private String name;
    /*    */   private String portrait;
    /*    */   private Double points;
    /*    */   private Integer partner;
    private String phone;
    private String alipayName;
    private String alipayAccount;
    private String wxPay;
    private SceneEnum scene;
    private String state;
    private Date expireTime;
    private Date updateTime;
    private Date createTime;
    private String relation;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.MemberDTO)) return false;
        com.bss.entity.MemberDTO other = (com.bss.entity.MemberDTO) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
        Object this$mid = getMid(), other$mid = other.getMid();
        if (!Objects.equals(this$mid, other$mid)) return false;
        Object this$uid = getUid(), other$uid = other.getUid();
        if (!Objects.equals(this$uid, other$uid)) return false;
        Object this$unionid = getUnionid(), other$unionid = other.getUnionid();
        if (!Objects.equals(this$unionid, other$unionid)) return false;
        Object this$openid = getOpenid(), other$openid = other.getOpenid();
        if (!Objects.equals(this$openid, other$openid)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$portrait = getPortrait(), other$portrait = other.getPortrait();
        if (!Objects.equals(this$portrait, other$portrait)) return false;
        Object this$points = getPoints(), other$points = other.getPoints();
        if (!Objects.equals(this$points, other$points)) return false;
        Object this$partner = getPartner(), other$partner = other.getPartner();
        if (!Objects.equals(this$partner, other$partner)) return false;
        Object this$phone = getPhone(), other$phone = other.getPhone();
        if (!Objects.equals(this$phone, other$phone)) return false;
        Object this$alipayName = getAlipayName(), other$alipayName = other.getAlipayName();
        if (!Objects.equals(this$alipayName, other$alipayName))
            return false;
        Object this$alipayAccount = getAlipayAccount(), other$alipayAccount = other.getAlipayAccount();
        if (!Objects.equals(this$alipayAccount, other$alipayAccount))
            return false;
        Object this$wxPay = getWxPay(), other$wxPay = other.getWxPay();
        if (!Objects.equals(this$wxPay, other$wxPay)) return false;
        Object this$scene = getScene(), other$scene = other.getScene();
        if (!Objects.equals(this$scene, other$scene)) return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$expireTime = getExpireTime(), other$expireTime = other.getExpireTime();
        if (!Objects.equals(this$expireTime, other$expireTime))
            return false;
        Object this$updateTime = getUpdateTime(), other$updateTime = other.getUpdateTime();
        if (!Objects.equals(this$updateTime, other$updateTime))
            return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        if (!Objects.equals(this$createTime, other$createTime))
            return false;
        Object this$relation = getRelation(), other$relation = other.getRelation();
        return !(!Objects.equals(this$relation, other$relation));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.MemberDTO;
    }


    public String toString() {
        return "MemberDTO(id=" + getId() + ", merchant=" + getMerchant() + ", mid=" + getMid() + ", uid=" + getUid() + ", unionid=" + getUnionid() + ", openid=" + getOpenid() + ", name=" + getName() + ", portrait=" + getPortrait() + ", points=" + getPoints() + ", partner=" + getPartner() + ", phone=" + getPhone() + ", alipayName=" + getAlipayName() + ", alipayAccount=" + getAlipayAccount() + ", wxPay=" + getWxPay() + ", scene=" + getScene() + ", state=" + getState() + ", expireTime=" + getExpireTime() + ", updateTime=" + getUpdateTime() + ", createTime=" + getCreateTime() + ", relation=" + getRelation() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 17 */
        return this.id;
        /*    */
    }

    /*    */
    /* 14 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getMerchant() {
        /* 19 */
        return this.merchant;
        /*    */
    }

    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public String getMid() {
        /* 21 */
        return this.mid;
        /*    */
    }

    public void setMid(String mid) {
        this.mid = mid;
    }

    public String getUid() {
        /* 23 */
        return this.uid;
        /*    */
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public String getUnionid() {
        /* 25 */
        return this.unionid;
        /*    */
    }

    public void setUnionid(String unionid) {
        this.unionid = unionid;
    }

    public String getOpenid() {
        /* 27 */
        return this.openid;
        /*    */
    }

    public void setOpenid(String openid) {
        this.openid = openid;
    }

    public String getName() {
        /* 29 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPortrait() {
        /* 31 */
        return this.portrait;
        /*    */
    }

    public void setPortrait(String portrait) {
        this.portrait = portrait;
    }

    public Double getPoints() {
        /* 33 */
        return this.points;
        /*    */
    }

    public void setPoints(Double points) {
        this.points = points;
    }

    public Integer getPartner() {
        /* 35 */
        return this.partner;
        /*    */
    }

    public void setPartner(Integer partner) {
        this.partner = partner;
    }

    public String getPhone() {
        /* 37 */
        return this.phone;
        /*    */
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getAlipayName() {
        /* 39 */
        return this.alipayName;
        /*    */
    }

    public void setAlipayName(String alipayName) {
        this.alipayName = alipayName;
    }

    public String getAlipayAccount() {
        /* 41 */
        return this.alipayAccount;
        /*    */
    }

    public void setAlipayAccount(String alipayAccount) {
        this.alipayAccount = alipayAccount;
    }

    public String getWxPay() {
        /* 43 */
        return this.wxPay;
        /*    */
    }

    public void setWxPay(String wxPay) {
        this.wxPay = wxPay;
    }

    public SceneEnum getScene() {
        /* 45 */
        return this.scene;
        /*    */
    }

    public void setScene(SceneEnum scene) {
        this.scene = scene;
    }

    public String getState() {
        /* 47 */
        return this.state;
        /*    */
    }

    public void setState(String state) {
        this.state = state;
    }

    public Date getExpireTime() {
        /* 49 */
        return this.expireTime;
        /*    */
    }

    public void setExpireTime(Date expireTime) {
        this.expireTime = expireTime;
    }

    public Date getUpdateTime() {
        /* 51 */
        return this.updateTime;
        /*    */
    }

    public void setUpdateTime(Date updateTime) {
        this.updateTime = updateTime;
    }

    public Date getCreateTime() {
        /* 53 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }

    public String getRelation() {
        /* 55 */
        return this.relation;
        /*    */
    }

    public void setRelation(String relation) {
        this.relation = relation;
    }
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\MemberDTO.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */