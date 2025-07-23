/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;

import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("member")
/*    */ public class MemberVo implements Serializable {
    /*    */   private String merchant;
    /*    */   private String unionid;
    /*    */   private String openid;
    /*    */   private Integer scene;
    /*    */   private String mid;

    /*    */
    /* 13 */
    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public void setUnionid(String unionid) {
        this.unionid = unionid;
    }

    public void setOpenid(String openid) {
        this.openid = openid;
    }

    public void setScene(Integer scene) {
        this.scene = scene;
    }

    public void setMid(String mid) {
        this.mid = mid;
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.MemberVo)) return false;
        com.bss.entity.MemberVo other = (com.bss.entity.MemberVo) o;
        if (!other.canEqual(this)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
        Object this$unionid = getUnionid(), other$unionid = other.getUnionid();
        if (!Objects.equals(this$unionid, other$unionid)) return false;
        Object this$openid = getOpenid(), other$openid = other.getOpenid();
        if (!Objects.equals(this$openid, other$openid)) return false;
        Object this$scene = getScene(), other$scene = other.getScene();
        if (!Objects.equals(this$scene, other$scene)) return false;
        Object this$mid = getMid(), other$mid = other.getMid();
        return !(!Objects.equals(this$mid, other$mid));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.MemberVo;
    }


    public String toString() {
        return "MemberVo(merchant=" + getMerchant() + ", unionid=" + getUnionid() + ", openid=" + getOpenid() + ", scene=" + getScene() + ", mid=" + getMid() + ")";
    }

    /*    */
    /*    */
    public String getMerchant() {
        /* 16 */
        return this.merchant;
        /*    */
    }

    public String getUnionid() {
        /* 18 */
        return this.unionid;
        /*    */
    }

    public String getOpenid() {
        /* 20 */
        return this.openid;
        /*    */
    }

    public Integer getScene() {
        /* 22 */
        return this.scene;
        /*    */
    }

    public String getMid() {
        /* 24 */
        return this.mid;
        /*    */
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\MemberVo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */