/*    */
package com.bss.entity;

import java.util.Objects;

/*    */
/*    */
/*    */ public class PageAppModel
        /*    */ {
    /*    */   private Long mid;
    /*    */   private Integer pageIndex;
    /*    */   private Integer size;

    public PageAppModel(Long mid, Integer pageIndex, Integer size) {
        /* 12 */
        this.mid = mid;
        this.pageIndex = pageIndex;
        this.size = size;
        /*    */
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.PageAppModel)) return false;
        com.bss.entity.PageAppModel other = (com.bss.entity.PageAppModel) o;
        if (!other.canEqual(this)) return false;
        Object this$mid = getMid(), other$mid = other.getMid();
        if (!Objects.equals(this$mid, other$mid)) return false;
        Object this$pageIndex = getPageIndex(), other$pageIndex = other.getPageIndex();
        if (!Objects.equals(this$pageIndex, other$pageIndex))
            return false;
        Object this$size = getSize(), other$size = other.getSize();
        return !(!Objects.equals(this$size, other$size));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.PageAppModel;
    }


    public String toString() {
        return "PageAppModel(mid=" + getMid() + ", pageIndex=" + getPageIndex() + ", size=" + getSize() + ")";
    }

    /*    */
    /* 15 */
    public Long getMid() {
        return this.mid;
    }

    /*    */
    /*    */
    public void setMid(Long mid) {
        /* 11 */
        this.mid = mid;
    }

    /* 16 */
    public Integer getPageIndex() {
        return this.pageIndex;
    }

    public void setPageIndex(Integer pageIndex) {
        this.pageIndex = pageIndex;
    }

    public Integer getSize() {
        /* 17 */
        return this.size;
        /*    */
    }

    public void setSize(Integer size) {
        this.size = size;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\PageAppModel.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */