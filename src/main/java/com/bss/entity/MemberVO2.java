/*    */
package com.bss.entity;

import java.util.Objects;

/*    */
/*    */ public class MemberVO2 {
    /*    */   private Integer id;
    /*    */   private String name;
    /*    */   private String portrait;
    /*    */   private Double points;
    /*    */   private String phone;
    /*    */   private String mid;

    /*    */
    /* 11 */
    public MemberVO2(Integer id, String name, String portrait, Double points, String phone, String mid) {
        this.id = id;
        this.name = name;
        this.portrait = portrait;
        this.points = points;
        this.phone = phone;
        this.mid = mid;
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.MemberVO2)) return false;
        com.bss.entity.MemberVO2 other = (com.bss.entity.MemberVO2) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$portrait = getPortrait(), other$portrait = other.getPortrait();
        if (!Objects.equals(this$portrait, other$portrait)) return false;
        Object this$points = getPoints(), other$points = other.getPoints();
        if (!Objects.equals(this$points, other$points)) return false;
        Object this$phone = getPhone(), other$phone = other.getPhone();
        if (!Objects.equals(this$phone, other$phone)) return false;
        Object this$mid = getMid(), other$mid = other.getMid();
        return !(!Objects.equals(this$mid, other$mid));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.MemberVO2;
    }


    public String toString() {
        return "MemberVO2(id=" + getId() + ", name=" + getName() + ", portrait=" + getPortrait() + ", points=" + getPoints() + ", phone=" + getPhone() + ", mid=" + getMid() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 15 */
        return this.id;
        /*    */
    }

    /* 12 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        /* 17 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPortrait() {
        /* 19 */
        return this.portrait;
        /*    */
    }

    public void setPortrait(String portrait) {
        this.portrait = portrait;
    }

    public Double getPoints() {
        /* 21 */
        return this.points;
        /*    */
    }

    public void setPoints(Double points) {
        this.points = points;
    }

    public String getPhone() {
        /* 23 */
        return this.phone;
        /*    */
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getMid() {
        /* 25 */
        return this.mid;
        /*    */
    }

    public void setMid(String mid) {
        this.mid = mid;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\MemberVO2.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */